use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Display,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use assert_matches::assert_matches;
use candid::{CandidType, Decode, Encode, Nat, Principal};
use client::deposit;
use cycles_ledger::{
    config::{self, Config as LedgerConfig, FEE, MAX_MEMO_LENGTH},
    endpoints::{
        BlockWithId, ChangeIndexId, CmcCreateCanisterError, CreateCanisterFromArgs,
        CreateCanisterFromError, DataCertificate, DepositResult, GetBlocksResult, LedgerArgs,
        UpgradeArgs, WithdrawArgs, WithdrawError, WithdrawFromArgs, WithdrawFromError,
    },
    memo::encode_withdraw_memo,
    storage::{
        transfer_from::{expired_approval, CANNOT_TRANSFER_FROM_ZERO, DENIED_OWNER},
        Block, Hash,
        Operation::{self, Approve, Burn, Mint, Transfer},
        Transaction, CREATE_CANISTER_MEMO, PENALIZE_MEMO, REFUND_MEMO,
    },
};
use cycles_ledger::{
    endpoints::{
        CmcCreateCanisterArgs, CreateCanisterArgs, CreateCanisterError, CreateCanisterSuccess,
    },
    storage::CMC_PRINCIPAL,
};
use depositor::endpoints::InitArg as DepositorInitArg;
use escargot::CargoBuild;
use gen::{CyclesLedgerCall, CyclesLedgerInMemory};
use ic_cbor::CertificateToCbor;
use ic_cdk::api::{
    call::RejectionCode,
    management_canister::{main::CanisterStatusResponse, provisional::CanisterSettings},
};
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{
    hash_tree::{HashTreeNode, SubtreeLookupResult},
    Certificate, HashTree, LookupResult,
};
use ic_test_state_machine_client::{CallError, ErrorCode, StateMachine, WasmResult};
use icrc_ledger_types::icrc106::errors::Icrc106Error;
use icrc_ledger_types::{
    icrc::generic_metadata_value::MetadataValue,
    icrc1::{
        account::{Account, DEFAULT_SUBACCOUNT},
        transfer::{Memo, TransferArg as TransferArgs, TransferError},
    },
    icrc103::get_allowances::{Allowances, GetAllowancesArgs},
    icrc2::{
        allowance::Allowance,
        approve::{ApproveArgs, ApproveError},
        transfer_from::{TransferFromArgs, TransferFromError},
    },
};
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde_bytes::ByteBuf;
use tempfile::TempDir;

use crate::{
    client::{
        canister_status, create_canister, fail_next_create_canister_with, get_block,
        icrc1_balance_of,
    },
    gen::IsCyclesLedger,
};

mod client;
mod gen;

// Like assert_eq but uses Display instead of Debug
#[track_caller]
fn assert_display_eq<T>(left: T, right: T)
where
    T: Display + PartialEq,
{
    if left != right {
        panic!("The two values are different\nleft:  {left}\nright: {right}");
    }
}

// Like assert_eq but uses Display instead of Debug
#[track_caller]
fn assert_vec_display_eq<T, U, V>(lefts: U, rights: V)
where
    T: Display + PartialEq,
    U: AsRef<[T]>,
    V: AsRef<[T]>,
{
    if lefts.as_ref().len() != rights.as_ref().len() {
        let left = lefts
            .as_ref()
            .iter()
            .map(|t| format!("  {t}"))
            .collect::<Vec<_>>()
            .join("\n");
        let right = rights
            .as_ref()
            .iter()
            .map(|t| format!("  {t}"))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "The two vectors of values have different length.
            \nleft.len():  {}\n right.len(): {}\n\nThe full list of values was\
            \nleft:\n{left}\nright:\n{right}",
            lefts.as_ref().len(),
            rights.as_ref().len(),
        );
    }

    let diff = lefts
        .as_ref()
        .iter()
        .zip(rights.as_ref().iter())
        .enumerate()
        .filter(|(_, (left, right))| left != right)
        .collect::<Vec<_>>();
    if !diff.is_empty() {
        let diff = diff
            .iter()
            .map(|(i, (l, r))| format!("  at index: {i}\n    left:  {l}\n    right: {r}"))
            .collect::<Vec<_>>()
            .join("\n");
        let left = lefts
            .as_ref()
            .iter()
            .map(|t| format!("  {t}"))
            .collect::<Vec<_>>()
            .join("\n");
        let right = rights
            .as_ref()
            .iter()
            .map(|t| format!("  {t}"))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "The two vectors of values are different. Differences are\
            \n{diff}\n\nThe full list of values was\
            \nleft:\n{left}\nright:\n{right}"
        );
    }
}

fn new_state_machine() -> StateMachine {
    let mut state_machine_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();

    state_machine_path.push("ic-test-state-machine");

    if !state_machine_path.exists() {
        #[cfg(target_os = "macos")]
        let platform: &str = "darwin";
        #[cfg(target_os = "linux")]
        let platform: &str = "linux";
        let suggested_ic_commit = "072b2a6586c409efa88f2244d658307ff3a645d8";

        // not run automatically because parallel test execution screws this up
        panic!("state machine binary does not exist. Please run the following command and try again: ./download-state-machine.sh {suggested_ic_commit} {platform}");
    }
    StateMachine::new(state_machine_path.to_str().unwrap(), false)
}

lazy_static! {
    static ref WASMS: Mutex<HashMap<&'static str, Vec<u8>>> = Mutex::new(HashMap::new());
}

fn get_wasm(name: &'static str) -> Vec<u8> {
    WASMS
        .lock()
        .unwrap()
        .entry(name)
        .or_insert_with(|| build_wasm(name))
        .to_owned()
}

fn build_wasm(name: &str) -> Vec<u8> {
    if name == "cycles-ledger" {
        let tmp_dir = TempDir::with_prefix("cycles-ledger-tmp-dir").unwrap();
        let cargo_manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let cargo_manifest_dir = PathBuf::from(cargo_manifest_dir);
        let docker_build_script = cargo_manifest_dir
            .join("../scripts/docker-build")
            .canonicalize()
            .unwrap();
        let exit_status = Command::new(docker_build_script.clone())
            .arg(tmp_dir.path().canonicalize().unwrap())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
        if !exit_status.success() {
            panic!(
                "{} failed with exit status {exit_status}",
                docker_build_script.display()
            )
        }
        let wasm_file = tmp_dir.path().join("cycles-ledger.wasm.gz");
        std::fs::read(wasm_file.clone())
            .unwrap_or_else(|e| panic!("{} file not found: {e}", wasm_file.display()))
    } else {
        let binary = CargoBuild::new()
            .manifest_path("../Cargo.toml")
            .target("wasm32-unknown-unknown")
            .bin(name)
            .arg("--release")
            .arg("--features")
            .arg("testing")
            .run()
            .expect("Unable to run cargo build");
        std::fs::read(binary.path()).unwrap_or_else(|_| panic!("{} wasm file not found", name))
    }
}

fn install_ledger(env: &StateMachine) -> Principal {
    install_ledger_with_conf(env, LedgerConfig::default())
}

fn install_ledger_with_conf(env: &StateMachine, config: LedgerConfig) -> Principal {
    let canister = env.create_canister(None);
    let init_args = Encode!(&LedgerArgs::Init(config)).unwrap();
    env.install_canister(canister, get_wasm("cycles-ledger"), init_args, None);
    canister
}

fn install_depositor(env: &StateMachine, ledger_id: Principal) -> Principal {
    let depositor_init_arg = Encode!(&DepositorInitArg { ledger_id }).unwrap();
    let canister = env.create_canister(None);
    env.install_canister(canister, get_wasm("depositor"), depositor_init_arg, None);
    env.add_cycles(canister, u128::MAX);
    canister
}

fn install_fake_cmc(env: &StateMachine) -> Principal {
    #[derive(CandidType, Default)]
    struct ProvisionalCreateArg {
        specified_id: Option<Principal>,
    }
    #[derive(CandidType, candid::Deserialize)]
    struct ProvisionalCreateResponse {
        canister_id: Principal,
    }
    let WasmResult::Reply(response) = env
        .update_call(
            Principal::from_text("aaaaa-aa").unwrap(),
            Principal::anonymous(),
            "provisional_create_canister_with_cycles",
            Encode!(&ProvisionalCreateArg {
                specified_id: Some(CMC_PRINCIPAL),
            })
            .unwrap(),
        )
        .unwrap()
    else {
        panic!("Failed to create CMC")
    };
    let response = Decode!(&response, ProvisionalCreateResponse).unwrap();
    assert_eq!(response.canister_id, CMC_PRINCIPAL);
    env.add_cycles(CMC_PRINCIPAL, u128::MAX / 2);
    env.install_canister(
        CMC_PRINCIPAL,
        get_wasm("fake-cmc"),
        Encode!(&Vec::<u8>::new()).unwrap(),
        None,
    );
    CMC_PRINCIPAL
}

/** Create an ICRC-1 Account from two numbers by using their big-endian representation */
pub fn account(owner: u64, subaccount: Option<u64>) -> Account {
    Account {
        owner: Principal::from_slice(owner.to_be_bytes().as_slice()),
        subaccount: subaccount.map(|subaccount| {
            let mut subaccount_bytes = [0u8; 32];
            subaccount_bytes[24..32].copy_from_slice(subaccount.to_be_bytes().as_slice());
            subaccount_bytes
        }),
    }
}

struct TestEnv {
    pub state_machine: StateMachine,
    pub ledger_id: Principal,
    pub depositor_id: Principal,
    #[allow(dead_code)]
    pub cmc_id: Principal,
}

impl TestEnv {
    fn setup() -> Self {
        let state_machine = new_state_machine();
        let cmc_id = install_fake_cmc(&state_machine);
        let ledger_id = install_ledger(&state_machine);
        let depositor_id = install_depositor(&state_machine, ledger_id);
        Self {
            state_machine,
            ledger_id,
            depositor_id,
            cmc_id,
        }
    }

    fn setup_with_ledger_conf(conf: LedgerConfig) -> Self {
        let state_machine = new_state_machine();
        let cmc_id = install_fake_cmc(&state_machine);
        let ledger_id = install_ledger_with_conf(&state_machine, conf);
        let depositor_id = install_depositor(&state_machine, ledger_id);
        Self {
            state_machine,
            ledger_id,
            depositor_id,
            cmc_id,
        }
    }
    fn fail_next_create_canister_with(&self, error: CmcCreateCanisterError) {
        client::fail_next_create_canister_with(&self.state_machine, error)
    }

    fn upgrade_ledger(&self, args: Option<UpgradeArgs>) -> Result<(), CallError> {
        let arg = Encode!(&Some(LedgerArgs::Upgrade(args))).unwrap();
        self.state_machine
            .upgrade_canister(self.ledger_id, get_wasm("cycles-ledger"), arg, None)
    }

    fn create_canister(
        &self,
        caller: Principal,
        args: CreateCanisterArgs,
    ) -> Result<CreateCanisterSuccess, CreateCanisterError> {
        client::create_canister(&self.state_machine, self.ledger_id, caller, args)
    }

    fn create_canister_from(
        &self,
        caller: Principal,
        args: CreateCanisterFromArgs,
    ) -> Result<CreateCanisterSuccess, CreateCanisterFromError> {
        client::create_canister_from(&self.state_machine, self.ledger_id, caller, args)
    }

    fn create_canister_from_or_trap(
        &self,
        caller: Principal,
        args: CreateCanisterFromArgs,
    ) -> CreateCanisterSuccess {
        client::create_canister_from(&self.state_machine, self.ledger_id, caller, args.clone())
        .unwrap_or_else(|err| {
            panic!(
                "Call to create_canister_from({args:?}) from caller {caller} failed with error {err:?}"
            )
        })
    }

    fn canister_status(&self, caller: Principal, canister_id: Principal) -> CanisterStatusResponse {
        client::canister_status(&self.state_machine, canister_id, caller)
    }

    fn deposit(&self, to: Account, amount: u128, memo: Option<Memo>) -> DepositResult {
        client::deposit(&self.state_machine, self.depositor_id, to, amount, memo)
    }

    fn get_all_blocks(&self) -> Vec<Block> {
        self.get_all_blocks_with_ids()
            .into_iter()
            .map(|bid| Block::from_value(bid.block).unwrap())
            .collect()
    }

    fn get_all_blocks_with_ids(&self) -> Vec<BlockWithId> {
        let mut blocks: Vec<BlockWithId> = vec![];
        loop {
            let start = blocks
                .last()
                .map_or(Nat::from(0u64), |block| block.id.clone() + 1u64);
            let res = self.icrc3_get_blocks(vec![(start, Nat::from(u64::MAX))]);
            if res.blocks.is_empty() {
                break;
            }
            blocks.extend(res.blocks);
            if blocks.len() >= res.log_length {
                break;
            }
        }

        blocks
    }

    fn get_block(&self, block_index: Nat) -> Block {
        client::get_block(&self.state_machine, self.ledger_id, block_index)
    }

    fn get_block_hash(&self, block_index: Nat) -> [u8; 32] {
        self.get_block(block_index).hash()
    }

    fn number_of_blocks(&self) -> Nat {
        self.icrc3_get_blocks(vec![(0u8, 1u8)]).log_length
    }

    fn icrc1_balance_of(&self, account: Account) -> u128 {
        client::icrc1_balance_of(&self.state_machine, self.ledger_id, account)
    }

    fn icrc1_fee(&self) -> u128 {
        client::icrc1_fee(&self.state_machine, self.ledger_id)
    }

    fn icrc1_metadata(&self) -> Vec<(String, MetadataValue)> {
        client::icrc1_metadata(&self.state_machine, self.ledger_id)
    }

    fn icrc1_total_supply(&self) -> u128 {
        client::icrc1_total_supply(&self.state_machine, self.ledger_id)
    }

    fn icrc1_transfer(&self, caller: Principal, args: TransferArgs) -> Result<Nat, TransferError> {
        client::icrc1_transfer(&self.state_machine, self.ledger_id, caller, args)
    }

    fn icrc1_transfer_or_trap(&self, caller: Principal, args: TransferArgs) -> Nat {
        self.icrc1_transfer(caller, args.clone())
            .unwrap_or_else(|err| {
                panic!(
                    "Call to icrc1_transfer({args:?}) from caller {caller} failed with error {err}"
                )
            })
    }

    fn icrc2_allowance(&self, from: Account, spender: Account) -> Allowance {
        client::icrc2_allowance(&self.state_machine, self.ledger_id, from, spender)
    }

    fn icrc2_approve(&self, caller: Principal, args: ApproveArgs) -> Result<Nat, ApproveError> {
        client::icrc2_approve(&self.state_machine, self.ledger_id, caller, args)
    }

    fn icrc2_approve_or_trap(&self, caller: Principal, args: ApproveArgs) -> Nat {
        self.icrc2_approve(caller, args.clone())
            .unwrap_or_else(|err|
                panic!("Call to icrc2_approve({args:?}) from caller {caller} failed with error {err:?}"))
    }

    fn icrc103_get_allowances_or_panic(
        &self,
        caller: Principal,
        args: GetAllowancesArgs,
    ) -> Allowances {
        client::icrc103_get_allowances(&self.state_machine, self.ledger_id, caller, args)
            .expect("failed to list allowances")
    }

    fn icrc106_index_principal(&self) -> Result<Principal, Icrc106Error> {
        client::icrc106_get_index_principal(&self.state_machine, self.ledger_id)
    }

    fn icrc2_transfer_from(
        &self,
        caller: Principal,
        args: TransferFromArgs,
    ) -> Result<Nat, TransferFromError> {
        client::icrc2_transfer_from(&self.state_machine, self.ledger_id, caller, args)
    }

    fn icrc2_transfer_from_or_trap(&self, caller: Principal, args: TransferFromArgs) -> Nat {
        self.icrc2_transfer_from(caller, args.clone())
            .unwrap_or_else(|err|
                panic!("Call to icrc2_transfer_from({args:?}) from caller {caller} failed with error {err:?}"))
    }

    fn icrc3_get_blocks<N: Into<Nat>>(&self, start_lengths: Vec<(N, N)>) -> GetBlocksResult {
        client::icrc3_get_blocks(&self.state_machine, self.ledger_id, start_lengths)
    }

    fn icrc3_get_tip_certificate(&self) -> DataCertificate {
        client::get_tip_certificate(&self.state_machine, self.ledger_id)
    }

    fn nanos_since_epoch(&self) -> u128 {
        self.state_machine
            .time()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn nanos_since_epoch_u64(&self) -> u64 {
        (u64::MAX as u128)
            .min(self.nanos_since_epoch())
            .try_into()
            .unwrap()
    }

    fn advance_time(&self, duration: Duration) {
        self.state_machine.advance_time(duration);
        self.state_machine.tick();
    }

    fn withdraw(&self, caller: Principal, args: WithdrawArgs) -> Result<Nat, WithdrawError> {
        client::withdraw(&self.state_machine, self.ledger_id, caller, args)
    }

    fn withdraw_or_trap(&self, caller: Principal, args: WithdrawArgs) -> Nat {
        self.withdraw(caller, args.clone()).unwrap_or_else(|err| {
            panic!("Call to withdraw({args:?}) from caller {caller} failed with error {err:?}")
        })
    }

    fn withdraw_from(
        &self,
        caller: Principal,
        args: WithdrawFromArgs,
    ) -> Result<Nat, WithdrawFromError> {
        client::withdraw_from(&self.state_machine, self.ledger_id, caller, args)
    }

    fn withdraw_from_or_trap(&self, caller: Principal, args: WithdrawFromArgs) -> Nat {
        self.withdraw_from(caller, args.clone())
            .unwrap_or_else(|err| {
                panic!("Call to withdraw_from({args:?}) from caller {caller} failed with error {err:?}")
            })
    }

    fn transaction_hashes(&self) -> BTreeMap<[u8; 32], u64> {
        client::transaction_hashes(&self.state_machine, self.ledger_id)
    }

    fn transaction_timestamps(&self) -> BTreeMap<(u64, u64), ()> {
        client::transaction_timestamps(&self.state_machine, self.ledger_id)
    }

    // Validate that the given [response_certificate], [last_block_index], and [last_block_hash]
    // match the certified data from the ledger.
    #[track_caller]
    fn validate_certificate(&self, last_block_index: u64, last_block_hash: Hash) {
        let DataCertificate {
            certificate,
            hash_tree,
        } = self.icrc3_get_tip_certificate();
        let certificate = Certificate::from_cbor(certificate.as_slice()).unwrap();
        let root_key = self.state_machine.root_key();
        assert_matches!(
            certificate.verify(self.ledger_id.as_slice(), &root_key),
            Ok(_)
        );

        let certified_data_path: [&[u8]; 3] = [
            "canister".as_bytes(),
            self.ledger_id.as_slice(),
            "certified_data".as_bytes(),
        ];

        let certified_data_hash = match certificate.tree.lookup_path(&certified_data_path) {
            LookupResult::Found(v) => v,
            _ => panic!("Unable to find the certificate_data_hash for the ledger canister in the hash_tree (hash_tree: {:?}, path: {:?})", certificate.tree, certified_data_path),
        };

        let hash_tree: HashTree = ciborium::de::from_reader(hash_tree.as_slice())
            .expect("Unable to deserialize CBOR encoded hash_tree");

        assert_eq!(certified_data_hash, hash_tree.digest());

        let expected_last_block_hash = match hash_tree.lookup_subtree([b"last_block_hash"]) {
            SubtreeLookupResult::Found(tree) => match tree.as_ref() {
                HashTreeNode::Leaf(last_block_hash) => last_block_hash.clone(),
                _ => panic!("last_block_hash value in the hash_tree should be a leaf"),
            },
            _ => panic!("last_block_hash not found in the response hash_tree"),
        };
        assert_eq!(last_block_hash.to_vec(), expected_last_block_hash);

        let expected_last_block_index = match hash_tree.lookup_subtree([b"last_block_index"]) {
            SubtreeLookupResult::Found(tree) => match tree.as_ref() {
                HashTreeNode::Leaf(last_block_index_bytes) => {
                    leb128::read::unsigned(&mut last_block_index_bytes.as_slice())
                        .expect("Unable to read last_block_index from the hash_tree")
                }
                _ => panic!("last_block_index value in the hash_tree should be a Leaf"),
            },
            _ => panic!("last_block_hash not found in the response hash_tree"),
        };
        assert_eq!(last_block_index, expected_last_block_index);
    }
}

impl IsCyclesLedger for TestEnv {
    fn execute(&mut self, call: &CyclesLedgerCall) -> Result<(), String> {
        use gen::CyclesLedgerCallArg::*;

        match &call.arg {
            Approve(args) => {
                let _approve_res = self
                    .icrc2_approve(call.caller.to_owned(), args.to_owned())
                    .map_err(|err| {
                        format!(
                            "Call to icrc2_approve({args:?}) from \
                                     caller {} failed with error {err:?}",
                            call.caller
                        )
                    })?;
            }
            Withdraw(args) => {
                let _withdraw_res = self
                    .withdraw(call.caller.to_owned(), args.to_owned())
                    .map_err(|err| {
                        format!(
                            "Call to withdraw({args:?}) from caller \
                                     {} failed with error {err:?})",
                            call.caller
                        )
                    })?;
            }
            Transfer(args) => {
                let _transfer_res = self
                    .icrc1_transfer(call.caller.to_owned(), args.to_owned())
                    .map_err(|err| {
                        format!(
                            "Call to icrc1_transfer({args:?}) from \
                                     caller {} failed with error {err}",
                            call.caller
                        )
                    })?;
            }
            TransferFrom(args) => {
                let _transfer_from_res = self
                    .icrc2_transfer_from(call.caller.to_owned(), args.to_owned())
                    .map_err(|err| {
                        format!(
                            "Call to icrc2_transfer_from({args:?}) \
                                     from caller {} failed with error {err:?}",
                            call.caller
                        )
                    })?;
            }
            Deposit { amount, arg } => {
                let _deposit_res = self.deposit(
                    arg.to.to_owned(),
                    amount.0.to_u128().unwrap(),
                    arg.memo.to_owned(),
                );
            }
        };
        Ok(())
    }
}

#[test]
fn test_deposit_flow() {
    let env = TestEnv::setup();
    let account0 = account(0, None);
    let fee = env.icrc1_fee();

    // 0.0 Check that the total supply is 0.
    assert_eq!(env.icrc1_total_supply(), 0u128);

    // 0.1 Check that the user doesn't have any tokens before the first deposit.
    assert_eq!(env.icrc1_balance_of(account0), 0u128);

    // 1 Make the first deposit to the user and check the result.
    let deposit_res = env.deposit(account0, 1_000_000_000 + fee, None);
    assert_eq!(deposit_res.block_index, Nat::from(0_u128));
    assert_eq!(deposit_res.balance, Nat::from(1_000_000_000_u128));

    // 1.0 Check that the right amount of tokens have been minted.
    assert_eq!(env.icrc1_total_supply(), 1_000_000_000);

    // 1.1 Check that the user has the right balance.
    assert_eq!(env.icrc1_balance_of(account0), 1_000_000_000);

    // 1.2 Check that the block created is correct:
    let block0 = env.get_block(deposit_res.block_index);
    assert_display_eq(
        &block0,
        &Block {
            // 1.2.0 first block has no parent hash.
            phash: None,
            // 1.2.1 effective fee of mint blocks is 0.
            effective_fee: Some(0),
            // 1.2.2 timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // 1.2.3 transaction.created_at_time is not set.
                created_at_time: None,
                // 1.2.4 transaction.memo is not set because
                // the user didn't set it.
                memo: None,
                // 1.2.5 transaction.operation is mint.
                operation: Operation::Mint {
                    // 1.2.6 transaction.operation.to is the user.
                    to: account0,
                    // 1.2.7 transaction.operation.amount is the deposited amount.
                    amount: 1_000_000_000,
                    // 1.2.8 transaction.operation.fee is the ledger fee.
                    fee,
                },
            },
        },
    );

    // 2 Make another deposit to the user and check the result.
    let memo = Memo::from(vec![0xa, 0xb, 0xc, 0xd, 0xe, 0xf]);
    let deposit_res = env.deposit(account0, 500_000_000 + fee, Some(memo.clone()));
    assert_eq!(deposit_res.block_index, Nat::from(1_u128));
    assert_eq!(deposit_res.balance, Nat::from(1_500_000_000_u128));

    // 2.0 Check that the right amount of tokens have been minted
    assert_eq!(env.icrc1_total_supply(), 1_500_000_000);

    // 2.1 Check that the user has the right balance after both deposits.
    assert_eq!(env.icrc1_balance_of(account0), 1_500_000_000);

    // 2.2 Check that the block created is correct:
    let block1 = env.get_block(deposit_res.block_index);
    assert_display_eq(
        &block1,
        &Block {
            // 2.2.0 second block has the first block hash as parent hash.
            phash: Some(block0.hash()),
            // 2.2.1 effective fee of mint blocks is 0.
            effective_fee: Some(0),
            // 2.2.2 timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // 2.2.3 transaction.created_at_time is not set.
                created_at_time: None,
                // 2.2.4 transaction.memo is the one set by the user.
                memo: Some(memo),
                // 2.2.5 transaction.operation is mint.
                operation: Operation::Mint {
                    // 2.2.6 transaction.operation.to is the user.
                    to: account0,
                    // 2.2.7 transaction.operation.amount is the deposited amount.
                    amount: 500_000_000,
                    // 2.2.8 transaction.operation.fee is the ledger fee.
                    fee,
                },
            },
        },
    );
}

#[test]
#[should_panic]
fn test_deposit_amount_below_fee() {
    let env = TestEnv::setup();
    let account1 = account(1, None);

    // Attempt to deposit fewer than [config::FEE] cycles. This call should panic.
    let _deposit_result = env.deposit(account1, config::FEE - 1, None);
}

#[test]
#[should_panic]
fn test_deposit_amount_same_as_fee() {
    let env = TestEnv::setup();
    let account1 = account(1, None);

    // The amount of cycles minted is the cycles attached - fee.
    // If the amount of cycles attached is equal to the fee then
    // the endpoint should panic because minting 0 cycles is
    // forbidden.
    let _deposit_result = env.deposit(account1, config::FEE, None);
}

#[test]
fn test_withdraw_flow() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let account1 = account(1, None);
    let account1_1 = account(1, Some(1));
    let account1_2 = account(1, Some(2));
    let account1_3 = account(1, Some(3));
    let account1_4 = account(1, Some(4));
    let withdraw_receiver = env.state_machine.create_canister(None);

    // make deposits to the user and check the result
    let deposit_res = env.deposit(account1, 1_000_000_000 + fee, None);
    assert_eq!(deposit_res.block_index, 0_u128);
    assert_eq!(deposit_res.balance, 1_000_000_000_u128);
    let _deposit_res = env.deposit(account1_1, 1_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account1_2, 1_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account1_3, 1_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account1_4, 1_000_000_000 + fee, None);
    let mut expected_total_supply = 5_000_000_000;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // withdraw cycles from main account
    let withdraw_receiver_balance = env.state_machine.cycle_balance(withdraw_receiver);
    let withdraw_amount = 500_000_000_u128;
    let withdraw_idx = env.withdraw_or_trap(
        account1.owner,
        WithdrawArgs {
            from_subaccount: account1.subaccount,
            to: withdraw_receiver,
            created_at_time: None,
            amount: Nat::from(withdraw_amount),
        },
    );
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.state_machine.cycle_balance(withdraw_receiver)
    );
    assert_eq!(
        env.icrc1_balance_of(account1),
        1_000_000_000 - withdraw_amount - FEE
    );
    expected_total_supply -= withdraw_amount + FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(withdraw_idx.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(withdraw_idx - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the Ledger. This is different from burn in
            // other Ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was not set.
                created_at_time: None,
                // The transaction.memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(encode_withdraw_memo(&withdraw_receiver)),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1,
                    spender: None,
                    // The transaction.operation.amount is the withdrawn amount.
                    amount: withdraw_amount,
                },
            },
        },
    );

    // withdraw cycles from subaccount
    let withdraw_receiver_balance = env.state_machine.cycle_balance(withdraw_receiver);
    let withdraw_amount = 100_000_000_u128;
    let withdraw_idx = env
        .withdraw(
            account1_1.owner,
            WithdrawArgs {
                from_subaccount: Some(*account1_1.effective_subaccount()),
                to: withdraw_receiver,
                created_at_time: None,
                amount: Nat::from(withdraw_amount),
            },
        )
        .unwrap();
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.state_machine.cycle_balance(withdraw_receiver)
    );
    assert_eq!(
        env.icrc1_balance_of(account1_1),
        1_000_000_000 - withdraw_amount - FEE
    );
    expected_total_supply -= withdraw_amount + FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(withdraw_idx.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(withdraw_idx - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the Ledger. This is different from burn in
            // other Ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was not set.
                created_at_time: None,
                // The transaction.memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(encode_withdraw_memo(&withdraw_receiver)),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1_1,
                    spender: None,
                    // The transaction.operation.amount is the withdrawn amount.
                    amount: withdraw_amount,
                },
            },
        },
    );

    // withdraw cycles from subaccount with created_at_time set
    let now = env.nanos_since_epoch_u64();
    let withdraw_receiver_balance = env.state_machine.cycle_balance(withdraw_receiver);
    let withdraw_amount = 300_000_000_u128;
    let withdraw_idx = env
        .withdraw(
            account1_3.owner,
            WithdrawArgs {
                from_subaccount: Some(*account1_3.effective_subaccount()),
                to: withdraw_receiver,
                created_at_time: Some(now),
                amount: Nat::from(withdraw_amount),
            },
        )
        .unwrap();
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.state_machine.cycle_balance(withdraw_receiver)
    );
    assert_eq!(
        env.icrc1_balance_of(account1_3),
        1_000_000_000 - withdraw_amount - FEE
    );
    expected_total_supply -= withdraw_amount + FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(withdraw_idx.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(withdraw_idx - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the Ledger. This is different from burn in
            // other Ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was set to now.
                created_at_time: Some(now),
                // The transaction.memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(encode_withdraw_memo(&withdraw_receiver)),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1_3,
                    spender: None,
                    // The transaction.operation.amount is the withdrawn amount.
                    amount: withdraw_amount,
                },
            },
        },
    );
}

// A test to check that `DuplicateError` is returned on a duplicate `withdraw` request
// and not `InsufficientFundsError`, in case of insufficient funds
// to execute it a second time.
#[test]
fn test_withdraw_duplicate() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let account1 = account(1, None);
    let withdraw_receiver = env.state_machine.create_canister(None);

    // make deposits to the user and check the result
    let deposit_res = env.deposit(account1, 1_000_000_000 + fee, None);
    assert_eq!(deposit_res.block_index, 0_u128);
    assert_eq!(deposit_res.balance, 1_000_000_000_u128);

    let now = env.nanos_since_epoch_u64();
    // withdraw cycles from main account
    let withdraw_receiver_balance = env.state_machine.cycle_balance(withdraw_receiver);
    let withdraw_amount = 900_000_000_u128;
    let withdraw_idx = env.withdraw_or_trap(
        account1.owner,
        WithdrawArgs {
            from_subaccount: None,
            to: withdraw_receiver,
            created_at_time: Some(now),
            amount: Nat::from(withdraw_amount),
        },
    );
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.state_machine.cycle_balance(withdraw_receiver)
    );
    assert_eq!(
        env.icrc1_balance_of(account1),
        1_000_000_000 - withdraw_amount - FEE
    );
    let expected_blocks = env.get_all_blocks();

    assert_eq!(
        WithdrawError::Duplicate {
            duplicate_of: withdraw_idx.clone(),
        },
        env.withdraw(
            account1.owner,
            WithdrawArgs {
                from_subaccount: None,
                to: withdraw_receiver,
                created_at_time: Some(now),
                amount: Nat::from(withdraw_amount),
            },
        )
        .unwrap_err()
    );

    assert_vec_display_eq(expected_blocks, env.get_all_blocks());
}

#[test]
fn test_withdraw_fails() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let account1 = account(1, None);

    // make the first deposit to the user and check the result
    let deposit_res = env.deposit(account1, 1_000_000_000_000 + fee, None);
    assert_eq!(deposit_res.block_index, Nat::from(0_u128));
    assert_eq!(deposit_res.balance, 1_000_000_000_000_u128);
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;

    // withdraw more than available
    let balance_before_attempt = env.icrc1_balance_of(account1);
    let withdraw_result = env
        .withdraw(
            account1.owner,
            WithdrawArgs {
                from_subaccount: account1.subaccount,
                to: env.depositor_id,
                created_at_time: None,
                amount: Nat::from(u128::MAX),
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_result,
        WithdrawError::InsufficientFunds {
            balance: Nat::from(1_000_000_000_000_u128)
        }
    );
    assert_eq!(balance_before_attempt, env.icrc1_balance_of(account1));
    let mut expected_total_supply = 1_000_000_000_000;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    // check that no new blocks was added.
    assert_vec_display_eq(&blocks, env.get_all_blocks_with_ids());

    // withdraw from empty subaccount
    let withdraw_result = env
        .withdraw(
            account1.owner,
            WithdrawArgs {
                from_subaccount: Some([5; 32]),
                to: env.depositor_id,
                created_at_time: None,
                amount: Nat::from(100_000_000_u128),
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_result,
        WithdrawError::InsufficientFunds {
            balance: Nat::from(0_u128)
        }
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply,);
    // check that no new blocks was added.
    assert_vec_display_eq(&blocks, env.get_all_blocks_with_ids());

    // withdraw cycles to user instead of canister
    let balance_before_attempt = env.icrc1_balance_of(account1);
    let self_authenticating_principal =
        Principal::from_text("luwgt-ouvkc-k5rx5-xcqkq-jx5hm-r2rj2-ymqjc-pjvhb-kij4p-n4vms-gqe")
            .unwrap();
    let withdraw_result = env
        .withdraw(
            account1.owner,
            WithdrawArgs {
                from_subaccount: account1.subaccount,
                to: self_authenticating_principal,
                created_at_time: None,
                amount: Nat::from(500_000_000_u128),
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_result,
        WithdrawError::InvalidReceiver {
            receiver: self_authenticating_principal
        }
    );
    assert_eq!(balance_before_attempt, env.icrc1_balance_of(account1));
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    // check that no new block was added.
    assert_vec_display_eq(&blocks, env.get_all_blocks_with_ids());

    // withdraw cycles to deleted canister
    let balance_before_attempt = env.icrc1_balance_of(account1);
    let deleted_canister = env.state_machine.create_canister(None);
    env.state_machine
        .stop_canister(deleted_canister, None)
        .unwrap();
    env.state_machine
        .delete_canister(deleted_canister, None)
        .unwrap();
    let withdraw_result = env
        .withdraw(
            account1.owner,
            WithdrawArgs {
                from_subaccount: account1.subaccount,
                to: deleted_canister,
                created_at_time: None,
                amount: Nat::from(500_000_000_u128),
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_result,
        WithdrawError::FailedToWithdraw {
            rejection_code: RejectionCode::DestinationInvalid,
            fee_block: Some(Nat::from(blocks.len() + 1)),
            rejection_reason: format!("Canister {deleted_canister} not found.")
        }
    );
    // the caller pays the fee twice: once for the burn block and
    // once for the refund block
    assert_eq!(
        balance_before_attempt - 2 * FEE,
        env.icrc1_balance_of(account1)
    );
    expected_total_supply -= 2 * FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply,);
    // the destination invalid error happens after the burn block
    // was created and balances were changed. In order to fix the
    // issue, the ledger creates a mint block to refund the amount.
    // Therefore we expect two new blocks, a burn of amount + fee
    // and a mint of amount.
    assert_eq!(blocks.len() + 2, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash()),
            effective_fee: Some(env.icrc1_fee()),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(encode_withdraw_memo(&deleted_canister)),
                operation: Operation::Burn {
                    from: account1,
                    spender: None,
                    amount: 500_000_000_u128,
                },
            },
        }
        .to_value(),
    };
    let refund_block = BlockWithId {
        id: Nat::from(blocks.len()) + 1u8,
        block: Block {
            phash: Some(burn_block.block.hash()),
            effective_fee: Some(0),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo(ByteBuf::from(PENALIZE_MEMO))),
                operation: Operation::Mint {
                    to: account1,
                    // refund the amount minus the fee to make
                    // the caller pay for the refund block too
                    amount: 500_000_000_u128 - FEE,
                    fee: 0,
                },
            },
        }
        .to_value(),
    };
    let blocks = blocks
        .into_iter()
        .chain([burn_block, refund_block])
        .collect::<Vec<_>>();
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());

    // user keeps the cycles if they don't have enough balance to pay the fee
    let account2 = account(2, None);
    let _deposit_res = env.deposit(account2, 2 * FEE + 1, None);
    let blocks = env.get_all_blocks_with_ids();
    let _withdraw_res = env
        .withdraw(
            account2.owner,
            WithdrawArgs {
                from_subaccount: account2.subaccount,
                to: env.depositor_id,
                created_at_time: None,
                amount: Nat::from(u128::MAX),
            },
        )
        .unwrap_err();
    assert_eq!(FEE + 1, env.icrc1_balance_of(account2));
    let _withdraw_res = env
        .withdraw(
            account2.owner,
            WithdrawArgs {
                from_subaccount: account2.subaccount,
                to: env.depositor_id,
                created_at_time: None,
                amount: Nat::from(u128::MAX),
            },
        )
        .unwrap_err();
    assert_eq!(FEE + 1, env.icrc1_balance_of(account2));
    // check that no new block was added.
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());

    // test withdraw deduplication
    let _deposit_res = env.deposit(account2, FEE * 4, None);
    let created_at_time = env.nanos_since_epoch_u64();
    let args = WithdrawArgs {
        from_subaccount: None,
        to: env.depositor_id,
        created_at_time: Some(created_at_time),
        amount: Nat::from(FEE),
    };
    let duplicate_of = env.withdraw_or_trap(account2.owner, args.clone());
    let blocks = env.get_all_blocks_with_ids();
    // the same withdraw should fail because created_at_time is set and the args are the same
    assert_eq!(
        env.withdraw(account2.owner, args),
        Err(WithdrawError::Duplicate { duplicate_of })
    );
    // check that no new block was added.
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());
}

#[test]
fn test_withdraw_from_flow() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let account1 = account(1, None);
    let account1_1 = account(1, Some(1));
    let account1_2 = account(1, Some(2));
    let account1_3 = account(1, Some(3));
    let account1_4 = account(1, Some(4));
    let withdrawer1 = account(102, None);
    let withdrawer1_1 = account(102, Some(1));
    let withdraw_receiver = env.state_machine.create_canister(None);

    // make deposits to the user and check the result
    let deposit_res = env.deposit(account1, 1_000_000_000 + fee, None);
    assert_eq!(deposit_res.block_index, 0_u128);
    assert_eq!(deposit_res.balance, 1_000_000_000_u128);
    let _deposit_res = env.deposit(account1_1, 1_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account1_2, 1_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account1_3, 1_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account1_4, 1_000_000_000 + fee, None);
    let mut expected_total_supply = 5_000_000_000;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // withdraw cycles from main account
    let withdraw_receiver_balance = env.state_machine.cycle_balance(withdraw_receiver);
    let withdraw_amount = 500_000_000_u128;
    env.icrc2_approve_or_trap(
        account1.owner,
        ApproveArgs {
            from_subaccount: None,
            spender: withdrawer1,
            amount: Nat::from(withdraw_amount + FEE),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    let withdraw_idx = env.withdraw_from_or_trap(
        withdrawer1.owner,
        WithdrawFromArgs {
            from: account1,
            to: withdraw_receiver,
            created_at_time: None,
            amount: Nat::from(withdraw_amount),
            spender_subaccount: withdrawer1.subaccount,
        },
    );
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.state_machine.cycle_balance(withdraw_receiver)
    );
    assert_eq!(
        env.icrc2_allowance(account1, withdrawer1),
        Allowance {
            allowance: 0_u128.into(),
            expires_at: None
        }
    );
    assert_eq!(
        env.icrc1_balance_of(account1),
        1_000_000_000 - withdraw_amount - FEE - FEE
    );
    expected_total_supply -= withdraw_amount + FEE + FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(withdraw_idx.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(withdraw_idx - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the ledger. This is different from burn in
            // other ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was not set.
                created_at_time: None,
                // The memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(encode_withdraw_memo(&withdraw_receiver)),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1,
                    spender: Some(withdrawer1),
                    // The  operation amount is the withdrawn amount.
                    amount: withdraw_amount,
                },
            },
        },
    );

    // withdraw cycles from subaccount
    let withdraw_receiver_balance = env.state_machine.cycle_balance(withdraw_receiver);
    let withdraw_amount = 100_000_000_u128;
    env.icrc2_approve_or_trap(
        account1_1.owner,
        ApproveArgs {
            from_subaccount: account1_1.subaccount,
            spender: withdrawer1,
            amount: Nat::from(withdraw_amount + FEE),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    let withdraw_idx = env.withdraw_from_or_trap(
        withdrawer1.owner,
        WithdrawFromArgs {
            from: account1_1,
            to: withdraw_receiver,
            created_at_time: None,
            amount: Nat::from(withdraw_amount),
            spender_subaccount: withdrawer1.subaccount,
        },
    );
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.state_machine.cycle_balance(withdraw_receiver)
    );
    assert_eq!(
        env.icrc2_allowance(account1_1, withdrawer1),
        Allowance {
            allowance: 0_u128.into(),
            expires_at: None
        }
    );
    assert_eq!(
        env.icrc1_balance_of(account1_1),
        1_000_000_000 - withdraw_amount - FEE - FEE
    );
    expected_total_supply -= withdraw_amount + FEE + FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(withdraw_idx.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(withdraw_idx - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the ledger. This is different from burn in
            // other ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was not set.
                created_at_time: None,
                // The memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(encode_withdraw_memo(&withdraw_receiver)),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1_1,
                    spender: Some(withdrawer1),
                    // The operation amount is the withdrawn amount.
                    amount: withdraw_amount,
                },
            },
        },
    );

    // withdraw cycles from subaccount with created_at_time set
    let now = env.nanos_since_epoch_u64();
    let withdraw_receiver_balance = env.state_machine.cycle_balance(withdraw_receiver);
    let withdraw_amount = 300_000_000_u128;
    env.icrc2_approve_or_trap(
        account1_3.owner,
        ApproveArgs {
            from_subaccount: account1_3.subaccount,
            spender: withdrawer1,
            amount: Nat::from(withdraw_amount + FEE),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    let withdraw_idx = env.withdraw_from_or_trap(
        withdrawer1.owner,
        WithdrawFromArgs {
            from: account1_3,
            to: withdraw_receiver,
            created_at_time: Some(now),
            amount: Nat::from(withdraw_amount),
            spender_subaccount: withdrawer1.subaccount,
        },
    );
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.state_machine.cycle_balance(withdraw_receiver)
    );
    assert_eq!(
        env.icrc2_allowance(account1_1, withdrawer1),
        Allowance {
            allowance: 0_u128.into(),
            expires_at: None
        }
    );
    assert_eq!(
        env.icrc1_balance_of(account1_3),
        1_000_000_000 - withdraw_amount - FEE - FEE
    );
    expected_total_supply -= withdraw_amount + FEE + FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(withdraw_idx.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(withdraw_idx - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the ledger. This is different from burn in
            // other ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was set to now.
                created_at_time: Some(now),
                // The memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(encode_withdraw_memo(&withdraw_receiver)),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1_3,
                    spender: Some(withdrawer1),
                    // The operation amount is the withdrawn amount.
                    amount: withdraw_amount,
                },
            },
        },
    );

    // withdraw cycles using spender subaccount
    let withdraw_receiver_balance = env.state_machine.cycle_balance(withdraw_receiver);
    let withdraw_amount = 500_000_000_u128;
    env.icrc2_approve_or_trap(
        account1_4.owner,
        ApproveArgs {
            from_subaccount: account1_4.subaccount,
            spender: withdrawer1_1,
            amount: Nat::from(withdraw_amount + FEE),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    let withdraw_idx = env.withdraw_from_or_trap(
        withdrawer1_1.owner,
        WithdrawFromArgs {
            from: account1_4,
            to: withdraw_receiver,
            created_at_time: None,
            amount: Nat::from(withdraw_amount),
            spender_subaccount: withdrawer1_1.subaccount,
        },
    );
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.state_machine.cycle_balance(withdraw_receiver)
    );
    assert_eq!(
        env.icrc2_allowance(account1_4, withdrawer1_1),
        Allowance {
            allowance: 0_u128.into(),
            expires_at: None
        }
    );
    assert_eq!(
        env.icrc1_balance_of(account1_4),
        1_000_000_000 - withdraw_amount - FEE - FEE
    );
    expected_total_supply -= withdraw_amount + FEE + FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(withdraw_idx.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(withdraw_idx - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the ledger. This is different from burn in
            // other ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was not set.
                created_at_time: None,
                // The memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(encode_withdraw_memo(&withdraw_receiver)),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1_4,
                    spender: Some(withdrawer1_1),
                    // The operation amount is the withdrawn amount.
                    amount: withdraw_amount,
                },
            },
        },
    );
}

#[test]
fn test_withdraw_from_fails() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let withdrawer1 = account(101, None);
    let account1 = account(1, None);
    let account1_1 = account(1, Some(1));
    let account1_2 = account(1, Some(2));
    let account1_3 = account(1, Some(3));
    let account1_4 = account(1, Some(4));
    let account1_5 = account(1, Some(5));
    let account1_6 = account(1, Some(6));
    let account1_7 = account(1, Some(7));

    // make the first deposit to the user and check the result
    let _deposit_res = env.deposit(account1, 1_000_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account1_1, 1_000_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account1_2, 1_000_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account1_3, 1_000_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account1_4, 4 * FEE + 10_000, None);
    let _deposit_res = env.deposit(account1_5, 1_000_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account1_6, 1_000_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account1_7, 3 * FEE + 10_000, None);
    let mut expected_total_supply = 6_000_500_020_000_u128;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // withdraw more than available in account
    env.icrc2_approve_or_trap(
        account1.owner,
        ApproveArgs {
            from_subaccount: account1.subaccount,
            spender: withdrawer1,
            amount: Nat::from(u128::MAX),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    let allowance_before_attempt = env.icrc2_allowance(account1, withdrawer1);
    let balance_before_attempt = env.icrc1_balance_of(account1);
    let withdraw_result = env
        .withdraw_from(
            withdrawer1.owner,
            WithdrawFromArgs {
                from: account1,
                spender_subaccount: withdrawer1.subaccount,
                to: env.depositor_id,
                created_at_time: None,
                amount: Nat::from(u128::MAX - FEE),
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_result,
        WithdrawFromError::InsufficientFunds {
            balance: Nat::from(balance_before_attempt)
        }
    );
    assert_eq!(
        allowance_before_attempt,
        env.icrc2_allowance(account1, withdrawer1)
    );
    assert_eq!(balance_before_attempt, env.icrc1_balance_of(account1));
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    // check that no new block was added.
    assert_vec_display_eq(&blocks, env.get_all_blocks_with_ids());

    // withdraw zero
    let withdraw_result = env
        .withdraw_from(
            withdrawer1.owner,
            WithdrawFromArgs {
                from: account1,
                spender_subaccount: withdrawer1.subaccount,
                to: env.depositor_id,
                created_at_time: None,
                amount: Nat::from(0_u128),
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_result,
        WithdrawFromError::GenericError {
            error_code: CANNOT_TRANSFER_FROM_ZERO.into(),
            message: "The withdraw_from 0 cycles is not possible".into()
        }
    );
    assert_eq!(
        allowance_before_attempt,
        env.icrc2_allowance(account1, withdrawer1)
    );
    assert_eq!(balance_before_attempt, env.icrc1_balance_of(account1));
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    // check that no new block was added.
    assert_vec_display_eq(&blocks, env.get_all_blocks_with_ids());

    // withdraw more than approved
    let approved_amount = 100_000_000_u128;
    env.icrc2_approve_or_trap(
        account1_1.owner,
        ApproveArgs {
            from_subaccount: account1_1.subaccount,
            spender: withdrawer1,
            amount: Nat::from(approved_amount),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    let allowance_before_attempt = env.icrc2_allowance(account1_1, withdrawer1);
    let balance_before_attempt = env.icrc1_balance_of(account1_1);
    let withdraw_result = env
        .withdraw_from(
            withdrawer1.owner,
            WithdrawFromArgs {
                from: account1_1,
                spender_subaccount: withdrawer1.subaccount,
                to: env.depositor_id,
                created_at_time: None,
                amount: Nat::from(approved_amount), // also costs FEE, therefore total_cost > approved_amount
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_result,
        WithdrawFromError::InsufficientAllowance {
            allowance: allowance_before_attempt.allowance.clone()
        }
    );
    assert_eq!(
        allowance_before_attempt,
        env.icrc2_allowance(account1_1, withdrawer1)
    );
    assert_eq!(balance_before_attempt, env.icrc1_balance_of(account1_1));
    expected_total_supply -= FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    // check that no new block was added.
    assert_vec_display_eq(&blocks, env.get_all_blocks_with_ids());

    // withdraw to non-canister principal
    let balance_before_attempt = env.icrc1_balance_of(account1);
    let self_authenticating_principal =
        Principal::from_text("luwgt-ouvkc-k5rx5-xcqkq-jx5hm-r2rj2-ymqjc-pjvhb-kij4p-n4vms-gqe")
            .unwrap();
    let withdraw_result = env
        .withdraw_from(
            withdrawer1.owner,
            WithdrawFromArgs {
                from: account1,
                to: self_authenticating_principal,
                created_at_time: None,
                amount: Nat::from(500_000_000_u128),
                spender_subaccount: withdrawer1.subaccount,
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_result,
        WithdrawFromError::InvalidReceiver {
            receiver: self_authenticating_principal
        }
    );
    assert_eq!(balance_before_attempt, env.icrc1_balance_of(account1));
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    // check that no new block was added.
    assert_vec_display_eq(&blocks, env.get_all_blocks_with_ids());

    // withdraw cycles to deleted canister
    env.icrc2_approve_or_trap(
        account1_2.owner,
        ApproveArgs {
            from_subaccount: account1_2.subaccount,
            spender: withdrawer1,
            amount: Nat::from(u128::MAX),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let allowance_before_attempt = env.icrc2_allowance(account1_2, withdrawer1);
    let balance_before_attempt = env.icrc1_balance_of(account1_2);
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    let deleted_canister = env.state_machine.create_canister(None);
    env.state_machine
        .stop_canister(deleted_canister, None)
        .unwrap();
    env.state_machine
        .delete_canister(deleted_canister, None)
        .unwrap();
    let withdraw_result = env
        .withdraw_from(
            withdrawer1.owner,
            WithdrawFromArgs {
                from: account1_2,
                spender_subaccount: withdrawer1.subaccount,
                to: deleted_canister,
                created_at_time: None,
                amount: Nat::from(500_000_000_u128),
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_result,
        WithdrawFromError::FailedToWithdrawFrom {
            rejection_code: RejectionCode::DestinationInvalid,
            withdraw_from_block: Some(Nat::from(blocks.len())),
            refund_block: Some(Nat::from(blocks.len() + 1)),
            approval_refund_block: Some(Nat::from(blocks.len() + 2)),
            rejection_reason: format!("Canister {deleted_canister} not found.")
        }
    );
    assert_eq!(
        balance_before_attempt - 3 * FEE,
        env.icrc1_balance_of(account1_2)
    );
    assert_eq!(
        allowance_before_attempt.allowance - 3 * FEE,
        env.icrc2_allowance(account1_2, withdrawer1).allowance
    );
    expected_total_supply -= 3 * FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply,);
    // the destination invalid error happens after the burn block
    // was created and balances were changed. In order to fix the
    // issue, the ledger creates a mint block to refund the amount and a new approval.
    // Therefore we expect three new blocks, a burn of amount + fee,
    // a mint of amount, and an approve of amount - fee.
    assert_eq!(blocks.len() + 3, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash()),
            effective_fee: Some(env.icrc1_fee()),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(encode_withdraw_memo(&deleted_canister)),
                operation: Operation::Burn {
                    from: account1_2,
                    spender: Some(withdrawer1),
                    amount: 500_000_000_u128,
                },
            },
        }
        .to_value(),
    };
    let refund_block = BlockWithId {
        id: Nat::from(blocks.len()) + 1u8,
        block: Block {
            phash: Some(burn_block.block.hash()),
            effective_fee: Some(0),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo(ByteBuf::from(PENALIZE_MEMO))),
                operation: Operation::Mint {
                    to: account1_2,
                    amount: 400_000_000_u128,
                    fee: 0,
                },
            },
        }
        .to_value(),
    };
    let approve_refund_block = BlockWithId {
        id: Nat::from(blocks.len()) + 2u8,
        block: Block {
            phash: Some(refund_block.block.hash()),
            effective_fee: Some(env.icrc1_fee()),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                operation: Operation::Approve {
                    from: account1_2,
                    spender: withdrawer1,
                    amount: u128::MAX - 3 * FEE,
                    expected_allowance: None,
                    expires_at: None,
                    fee: None,
                },
                created_at_time: None,
                memo: Some(Memo(ByteBuf::from(PENALIZE_MEMO))),
            },
        }
        .to_value(),
    };
    let blocks = blocks
        .into_iter()
        .chain([burn_block, refund_block, approve_refund_block])
        .collect::<Vec<_>>();
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());

    // allowance does not get refunded because it's not worth it
    env.icrc2_approve_or_trap(
        account1_3.owner,
        ApproveArgs {
            from_subaccount: account1_3.subaccount,
            spender: withdrawer1,
            amount: Nat::from(u128::MAX),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let balance_before_attempt = env.icrc1_balance_of(account1_3);
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    let withdraw_result = env
        .withdraw_from(
            withdrawer1.owner,
            WithdrawFromArgs {
                from: account1_3,
                spender_subaccount: withdrawer1.subaccount,
                to: deleted_canister,
                created_at_time: None,
                amount: Nat::from(FEE + 10_000_u128),
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_result,
        WithdrawFromError::FailedToWithdrawFrom {
            rejection_code: RejectionCode::DestinationInvalid,
            withdraw_from_block: Some(Nat::from(blocks.len())),
            refund_block: Some(Nat::from(blocks.len() + 1)),
            approval_refund_block: None,
            rejection_reason: format!("Canister {deleted_canister} not found.")
        }
    );
    assert_eq!(
        balance_before_attempt - 2 * FEE,
        env.icrc1_balance_of(account1_3)
    );
    assert_eq!(
        Nat::from(u128::MAX - 2 * FEE - 10_000),
        env.icrc2_allowance(account1_3, withdrawer1).allowance
    );
    expected_total_supply -= 2 * FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply,);
    // the destination invalid error happens after the burn block
    // was created and balances were changed. In order to fix the
    // issue, the ledger creates a mint block to refund the amount.
    // Refunding the approval is not worth it because it would cost more than the approval amount.
    // Therefore we expect two new blocks, a burn of amount + fee and a mint of amount.
    assert_eq!(blocks.len() + 2, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash()),
            effective_fee: Some(env.icrc1_fee()),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(encode_withdraw_memo(&deleted_canister)),
                operation: Operation::Burn {
                    from: account1_3,
                    spender: Some(withdrawer1),
                    amount: FEE + 10_000,
                },
            },
        }
        .to_value(),
    };
    let refund_block = BlockWithId {
        id: Nat::from(blocks.len()) + 1u8,
        block: Block {
            phash: Some(burn_block.block.hash()),
            effective_fee: Some(0),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo(ByteBuf::from(PENALIZE_MEMO))),
                operation: Operation::Mint {
                    to: account1_3,
                    amount: 10_000_u128,
                    fee: 0,
                },
            },
        }
        .to_value(),
    };
    let blocks = blocks
        .into_iter()
        .chain([burn_block, refund_block])
        .collect::<Vec<_>>();
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());

    // allowance does not get refunded because of insufficient funds
    env.icrc2_approve_or_trap(
        account1_4.owner,
        ApproveArgs {
            from_subaccount: account1_4.subaccount,
            spender: withdrawer1,
            amount: Nat::from(u128::MAX),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let balance_before_attempt = env.icrc1_balance_of(account1_4);
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    let withdraw_result = env
        .withdraw_from(
            withdrawer1.owner,
            WithdrawFromArgs {
                from: account1_4,
                spender_subaccount: withdrawer1.subaccount,
                to: deleted_canister,
                created_at_time: None,
                amount: Nat::from(FEE + 10_000),
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_result,
        WithdrawFromError::FailedToWithdrawFrom {
            rejection_code: RejectionCode::DestinationInvalid,
            withdraw_from_block: Some(Nat::from(blocks.len())),
            refund_block: Some(Nat::from(blocks.len() + 1)),
            approval_refund_block: None,
            rejection_reason: format!("Canister {deleted_canister} not found."),
        }
    );
    assert_eq!(
        balance_before_attempt - 2 * FEE,
        env.icrc1_balance_of(account1_4)
    );
    assert_eq!(
        Nat::from(u128::MAX - 2 * FEE - 10_000),
        env.icrc2_allowance(account1_4, withdrawer1).allowance
    );
    expected_total_supply -= 2 * FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply,);
    // the destination invalid error happens after the burn block
    // was created and balances were changed. In order to fix the
    // issue, the ledger creates a mint block to refund the amount and a new approval.
    // Refunding the approval is not possible because it would cost more than the account can pay for.
    // Therefore we expect two new blocks, a burn of amount + fee and a mint of amount.
    assert_eq!(blocks.len() + 2, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash()),
            effective_fee: Some(env.icrc1_fee()),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(encode_withdraw_memo(&deleted_canister)),
                operation: Operation::Burn {
                    from: account1_4,
                    spender: Some(withdrawer1),
                    amount: FEE + 10_000,
                },
            },
        }
        .to_value(),
    };
    let refund_block = BlockWithId {
        id: Nat::from(blocks.len()) + 1u8,
        block: Block {
            phash: Some(burn_block.block.hash()),
            effective_fee: Some(0),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo(ByteBuf::from(PENALIZE_MEMO))),
                operation: Operation::Mint {
                    to: account1_4,
                    amount: 10_000_u128,
                    fee: 0,
                },
            },
        }
        .to_value(),
    };
    let blocks = blocks
        .into_iter()
        .chain([burn_block, refund_block])
        .collect::<Vec<_>>();
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());

    // duplicate
    let withdraw_receiver_balance = env.state_machine.cycle_balance(env.depositor_id);
    let withdraw_amount = 200_000_000_u128;
    let created_at_time = env.nanos_since_epoch_u64();
    env.icrc2_approve_or_trap(
        account1_5.owner,
        ApproveArgs {
            from_subaccount: account1_5.subaccount,
            spender: withdrawer1,
            amount: Nat::from(u128::MAX),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    let blocks = env.get_all_blocks();
    let withdraw_idx = env.withdraw_from_or_trap(
        withdrawer1.owner,
        WithdrawFromArgs {
            from: account1_5,
            to: env.depositor_id,
            created_at_time: Some(created_at_time),
            amount: Nat::from(withdraw_amount),
            spender_subaccount: withdrawer1.subaccount,
        },
    );
    let withdraw_duplicate = env
        .withdraw_from(
            withdrawer1.owner,
            WithdrawFromArgs {
                spender_subaccount: withdrawer1.subaccount,
                from: account1_5,
                to: env.depositor_id,
                created_at_time: Some(created_at_time),
                amount: Nat::from(withdraw_amount),
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.state_machine.cycle_balance(env.depositor_id)
    );
    assert_eq!(env.get_all_blocks().len(), blocks.len() + 1);
    assert_eq!(
        WithdrawFromError::Duplicate {
            duplicate_of: withdraw_idx
        },
        withdraw_duplicate
    );
    expected_total_supply -= withdraw_amount + FEE + FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // approval refund does not affect expires_at
    let expires_at = env.nanos_since_epoch_u64() + 100_000_000;
    env.icrc2_approve_or_trap(
        account1_6.owner,
        ApproveArgs {
            from_subaccount: account1_6.subaccount,
            spender: withdrawer1,
            amount: Nat::from(u128::MAX),
            expected_allowance: None,
            expires_at: Some(expires_at),
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    env.withdraw_from(
        withdrawer1.owner,
        WithdrawFromArgs {
            from: account1_6,
            spender_subaccount: withdrawer1.subaccount,
            to: deleted_canister,
            created_at_time: None,
            amount: Nat::from(500_000_000_u128),
        },
    )
    .unwrap_err();
    expected_total_supply -= 3 * FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply,);
    // the destination invalid error happens after the burn block
    // was created and balances were changed. In order to fix the
    // issue, the ledger creates a mint block to refund the amount and a new approval.
    // Therefore we expect three new blocks, a burn of amount + fee,
    // a mint of amount, and an approve of amount - fee.
    assert_eq!(blocks.len() + 3, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash()),
            effective_fee: Some(env.icrc1_fee()),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(encode_withdraw_memo(&deleted_canister)),
                operation: Operation::Burn {
                    from: account1_6,
                    spender: Some(withdrawer1),
                    amount: 500_000_000_u128,
                },
            },
        }
        .to_value(),
    };
    let refund_block = BlockWithId {
        id: Nat::from(blocks.len()) + 1u8,
        block: Block {
            phash: Some(burn_block.block.hash()),
            effective_fee: Some(0),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo(ByteBuf::from(PENALIZE_MEMO))),
                operation: Operation::Mint {
                    to: account1_6,
                    amount: 400_000_000_u128,
                    fee: 0,
                },
            },
        }
        .to_value(),
    };
    let approve_refund_block = BlockWithId {
        id: Nat::from(blocks.len()) + 2u8,
        block: Block {
            phash: Some(refund_block.block.hash()),
            effective_fee: Some(env.icrc1_fee()),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                operation: Operation::Approve {
                    from: account1_6,
                    spender: withdrawer1,
                    amount: u128::MAX - 3 * FEE,
                    expected_allowance: None,
                    expires_at: Some(expires_at),
                    fee: None,
                },
                created_at_time: None,
                memo: Some(Memo(ByteBuf::from(PENALIZE_MEMO))),
            },
        }
        .to_value(),
    };
    let blocks = blocks
        .into_iter()
        .chain([burn_block, refund_block, approve_refund_block])
        .collect::<Vec<_>>();
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());

    // no refund if refunded tokens are insufficient to pay for a block
    env.icrc2_approve_or_trap(
        account1_7.owner,
        ApproveArgs {
            from_subaccount: account1_7.subaccount,
            spender: withdrawer1,
            amount: Nat::from(u128::MAX),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    let withdraw_result = env
        .withdraw_from(
            withdrawer1.owner,
            WithdrawFromArgs {
                from: account1_7,
                spender_subaccount: withdrawer1.subaccount,
                to: deleted_canister,
                created_at_time: None,
                amount: Nat::from(10_000_u128),
            },
        )
        .unwrap_err();
    assert_eq!(
        withdraw_result,
        WithdrawFromError::FailedToWithdrawFrom {
            rejection_code: RejectionCode::DestinationInvalid,
            withdraw_from_block: Some(Nat::from(blocks.len())),
            refund_block: None,
            approval_refund_block: None,
            rejection_reason: format!("Canister {deleted_canister} not found.")
        }
    );
    assert_eq!(Nat::from(0_u128), env.icrc1_balance_of(account1_7));
    assert_eq!(
        Nat::from(u128::MAX - FEE - 10_000),
        env.icrc2_allowance(account1_7, withdrawer1).allowance
    );
    expected_total_supply -= FEE + 10_000;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply,);
    // the destination invalid error happens after the burn block
    // was created and balances were changed. In order to fix the
    // issue, the ledger creates a mint block to refund the amount and a new approval.
    // Refunding the approval is not possible because it would cost more than the account can pay for.
    // Therefore we expect two new blocks, a burn of amount + fee and a mint of amount.
    assert_eq!(blocks.len() + 1, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash()),
            effective_fee: Some(env.icrc1_fee()),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(encode_withdraw_memo(&deleted_canister)),
                operation: Operation::Burn {
                    from: account1_7,
                    spender: Some(withdrawer1),
                    amount: 10_000_u128,
                },
            },
        }
        .to_value(),
    };
    let blocks = blocks.into_iter().chain([burn_block]).collect::<Vec<_>>();
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());
}

#[test]
fn test_approve_max_allowance_size() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let from = account(0, None);
    let spender = account(1, None);

    // Deposit funds
    assert_eq!(
        env.deposit(from, 1_000_000_000 + fee, None).balance,
        1_000_000_000_u128
    );

    // Largest possible allowance in terms of size in bytes - max amount and expiration
    let block_index = env
        .icrc2_approve(
            from.owner,
            ApproveArgs {
                from_subaccount: from.subaccount,
                spender,
                amount: Nat::from(u128::MAX),
                created_at_time: None,
                expected_allowance: None,
                expires_at: Some(u64::MAX),
                fee: None,
                memo: None,
            },
        )
        .expect("approve failed");
    assert_eq!(block_index, 1_u128);
    let allowance = env.icrc2_allowance(from, spender);
    assert_eq!(allowance.allowance, Nat::from(u128::MAX));
    assert_eq!(allowance.expires_at, Some(u64::MAX));
    assert_eq!(env.icrc1_balance_of(from), Nat::from(1_000_000_000 - FEE));
}

#[test]
fn test_icrc2_approve_self() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let from = account(0, None);

    // Deposit funds
    assert_eq!(
        env.deposit(from, 1_000_000_000 + fee, None).balance,
        1_000_000_000_u128
    );

    let args = ApproveArgs {
        from_subaccount: None,
        spender: from,
        amount: Nat::from(100_u128),
        expected_allowance: None,
        expires_at: None,
        fee: Some(Nat::from(FEE)),
        memo: None,
        created_at_time: None,
    };
    let err = env
        .state_machine
        .update_call(
            env.ledger_id,
            from.owner,
            "icrc2_approve",
            Encode!(&args).unwrap(),
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::CanisterCalledTrap);
    assert!(err.description.ends_with("self approval is not allowed"));
    assert_eq!(env.icrc1_balance_of(from), 1_000_000_000);
    assert_eq!(env.icrc1_total_supply(), 1_000_000_000);
}

#[test]
fn test_icrc2_approve_cap() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let from = account(0, None);
    let spender = account(1, None);

    // Deposit funds
    assert_eq!(
        env.deposit(from, 1_000_000_000 + fee, None).balance,
        1_000_000_000_u128
    );

    // Approve amount capped at u128::MAX
    let args = ApproveArgs {
        from_subaccount: None,
        spender,
        amount: Nat::from(
            BigUint::parse_bytes(b"1000000000000000000000000000000000000000", 10).unwrap(),
        ),
        expected_allowance: None,
        expires_at: None,
        fee: Some(Nat::from(FEE)),
        memo: None,
        created_at_time: None,
    };
    let _approve_res = env
        .icrc2_approve(from.owner, args)
        .expect("Unable to approve");
    let allowance = env.icrc2_allowance(from, spender);
    assert_eq!(allowance.allowance, Nat::from(u128::MAX));
    assert_eq!(allowance.expires_at, None);
    assert_eq!(env.icrc1_balance_of(from), Nat::from(1_000_000_000 - FEE));
}

// A test to check that `DuplicateError` is returned on a duplicate `approve` request
// and not `UnexpectedAllowanceError` if `expected_allowance` is set
#[test]
fn test_approve_duplicate() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let from = account(0, None);
    let spender = account(1, None);

    // Deposit funds
    assert_eq!(
        env.deposit(from, 1_000_000_000 + fee, None).balance,
        1_000_000_000u128
    );

    let now = env.nanos_since_epoch_u64();
    let args = ApproveArgs {
        from_subaccount: None,
        spender,
        amount: Nat::from(100u128),
        expected_allowance: Some(Nat::from(0u128)),
        expires_at: None,
        fee: Some(Nat::from(FEE)),
        memo: None,
        created_at_time: Some(now),
    };

    // first approve should work
    let duplicate_of = env
        .icrc2_approve(from.owner, args.clone())
        .expect("Unable to approve");
    let allowance = env.icrc2_allowance(from, spender);
    assert_eq!(allowance.allowance, Nat::from(100u128));
    assert_eq!(allowance.expires_at, None);
    assert_eq!(env.icrc1_balance_of(from), Nat::from(1_000_000_000 - FEE));

    // second approve should fail with [ApproveError::Duplicate]
    assert_eq!(
        env.icrc2_approve(from.owner, args),
        Err(ApproveError::Duplicate { duplicate_of })
    );
}

#[test]
fn test_approval_expiring() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let from = account(0, None);
    let spender1 = account(1, None);
    let spender2 = account(2, None);
    let spender3 = account(3, None);
    let spender4 = account(4, None);

    // Deposit funds
    assert_eq!(
        env.deposit(from, 1_000_000_000 + fee, None).balance,
        1_000_000_000_u128
    );

    // First approval expiring 1 hour from now.
    let expiration = env.nanos_since_epoch_u64() + Duration::from_secs(3600).as_nanos() as u64;
    let block_index = env
        .icrc2_approve(
            from.owner,
            ApproveArgs {
                from_subaccount: from.subaccount,
                spender: spender1,
                amount: Nat::from(100_000_000u32),
                memo: None,
                expires_at: Some(expiration),
                expected_allowance: None,
                fee: None,
                created_at_time: None,
            },
        )
        .expect("approve failed");
    assert_eq!(block_index, 1_u128);
    // TODO(FI-1205): check the block
    let allowance = env.icrc2_allowance(from, spender1);
    assert_eq!(allowance.allowance, Nat::from(100_000_000_u128));
    assert_eq!(allowance.expires_at, Some(expiration));

    // Second approval expiring 3 hour from now.
    let expiration_3h =
        env.nanos_since_epoch_u64() + Duration::from_secs(3 * 3600).as_nanos() as u64;
    let block_index = env
        .icrc2_approve(
            from.owner,
            ApproveArgs {
                from_subaccount: from.subaccount,
                spender: spender2,
                amount: Nat::from(200_000_000u32),
                memo: None,
                expires_at: Some(expiration_3h),
                expected_allowance: None,
                fee: None,
                created_at_time: None,
            },
        )
        .expect("approve failed");
    assert_eq!(block_index, 2_u128);
    // TODO(FI-1205): check the block
    let allowance = env.icrc2_allowance(from, spender2);
    assert_eq!(allowance.allowance, Nat::from(200_000_000_u128));
    assert_eq!(allowance.expires_at, Some(expiration_3h));

    // Test expired approval pruning, advance time 2 hours.
    env.state_machine
        .advance_time(Duration::from_secs(2 * 3600));
    env.state_machine.tick();

    // Add additional approval to trigger expired approval pruning
    env.icrc2_approve_or_trap(
        from.owner,
        ApproveArgs {
            from_subaccount: from.subaccount,
            spender: spender3,
            amount: Nat::from(300_000_000u32),
            memo: None,
            expires_at: Some(expiration_3h),
            expected_allowance: None,
            fee: None,
            created_at_time: None,
        },
    );
    // TODO(FI-1205): check the block
    let allowance = env.icrc2_allowance(from, spender3);
    assert_eq!(allowance.allowance, Nat::from(300_000_000_u128));
    assert_eq!(allowance.expires_at, Some(expiration_3h));

    let allowance = env.icrc2_allowance(from, spender1);
    assert_eq!(allowance.allowance, Nat::from(0_u128));
    assert_eq!(allowance.expires_at, None);
    let allowance = env.icrc2_allowance(from, spender2);
    assert_eq!(allowance.allowance, Nat::from(200_000_000_u128));
    assert_eq!(allowance.expires_at, Some(expiration_3h));

    // Should not be able to approve from/to a denied principal
    let owner = Principal::management_canister();
    env.icrc2_approve(
        owner,
        ApproveArgs {
            from_subaccount: None,
            spender: spender1,
            amount: Nat::from(100_000_000u32),
            memo: None,
            expires_at: None,
            expected_allowance: None,
            fee: None,
            created_at_time: None,
        },
    )
    .unwrap_err(); // TODO(FI-1206): check the error
    env.icrc2_approve(
        owner,
        ApproveArgs {
            from_subaccount: None,
            spender: spender2,
            amount: Nat::from(100_000_000u32),
            memo: None,
            expires_at: None,
            expected_allowance: None,
            fee: None,
            created_at_time: None,
        },
    )
    .unwrap_err(); // TODO(FI-1206): check the error

    // Approving works from the anonymous ID
    let from = Account {
        owner: Principal::anonymous(),
        subaccount: None,
    };
    env.deposit(from, 1_000_000_000, None);
    env.icrc2_approve(
        from.owner,
        ApproveArgs {
            from_subaccount: None,
            spender: spender4,
            amount: Nat::from(100_000_000u32),
            memo: None,
            expires_at: None,
            expected_allowance: None,
            fee: None,
            created_at_time: None,
        },
    )
    .unwrap();
    let allowance = env.icrc2_allowance(from, spender4);
    assert_eq!(allowance.allowance, Nat::from(100_000_000_u128));
    assert_eq!(allowance.expires_at, None);
}

// The test focuses on testing whether the correct
// sequence of allowances is returned for a given an (approver, spender) pair.
#[test]
fn test_allowance_listing_sequences() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();

    const NUM_PRINCIPALS: u64 = 3;
    const NUM_SUBACCOUNTS: u64 = 3;

    let mut approvers = vec![];
    let mut spenders = vec![];

    for pid in 1..NUM_PRINCIPALS + 1 {
        for sub in 0..NUM_SUBACCOUNTS {
            let approver = Account {
                owner: Principal::from_slice(&[pid as u8; 2]),
                subaccount: Some([sub as u8; 32]),
            };
            approvers.push(approver);
            env.deposit(approver, 100 * fee, None);
            spenders.push(Account {
                owner: Principal::from_slice(&[pid as u8 + NUM_PRINCIPALS as u8; 2]),
                subaccount: Some([sub as u8; 32]),
            });
        }
    }

    // Create approvals between all (approver, spender) pairs from `approvers` and `spenders`.
    // Additionally store all pairs in an array in sorted order in `approve_pairs`.
    // This allows us to check if the allowances returned by the `icrc103_get_allowances`
    // endpoint are correct - they will always form a contiguous subarray of `approve_pairs`.
    let mut approve_pairs = vec![];
    for approver in &approvers {
        for spender in &spenders {
            let approve_args = ApproveArgs {
                from_subaccount: approver.subaccount,
                spender: *spender,
                amount: Nat::from(10u64),
                expected_allowance: None,
                expires_at: None,
                fee: Some(Nat::from(FEE)),
                memo: None,
                created_at_time: None,
            };
            let _ = env
                .icrc2_approve(approver.owner, approve_args)
                .expect("approve failed");
            approve_pairs.push((approver, spender));
        }
    }
    assert!(approve_pairs.is_sorted());

    // Check if given allowances match the elements of `approve_pairs` starting at index `pair_index`.
    // Additionally check that the next element in `approve_pairs` has a different `from.owner`
    // and could not be part of the same response of `icrc103_get_allowances`.
    let check_allowances = |allowances: Allowances, pair_idx: usize, owner: Principal| {
        for i in 0..allowances.len() {
            let allowance = &allowances[i];
            let pair = approve_pairs[pair_idx + i];
            assert_eq!(allowance.from_account, *pair.0, "incorrect from account");
            assert_eq!(allowance.to_spender, *pair.1, "incorrect spender account");
        }
        let next_pair_idx = pair_idx + allowances.len();
        if next_pair_idx < approve_pairs.len() {
            assert_ne!(approve_pairs[next_pair_idx].0.owner, owner);
        }
    };

    // Create an Account that is lexicographically smaller than the given Account.
    // In the above Account generation scheme, the returned account will fall
    // between two approvers or spenders - we only modify the second byte of
    // the owner slice or the last byte of the subaccount slice.
    let prev_account = |account: &Account| {
        if account.subaccount.unwrap() == [0u8; 32] {
            let owner = account.owner.as_slice();
            let prev_owner = [owner[0], owner[1] - 1];
            Account {
                owner: Principal::from_slice(&prev_owner),
                subaccount: account.subaccount,
            }
        } else {
            let mut prev_subaccount = account.subaccount.unwrap();
            prev_subaccount[31] -= 1;
            Account {
                owner: account.owner,
                subaccount: Some(prev_subaccount),
            }
        }
    };

    let mut prev_from = None;
    for (idx, (&from, &spender)) in approve_pairs.iter().enumerate() {
        let mut args = GetAllowancesArgs {
            from_account: Some(from),
            prev_spender: None,
            take: None,
        };

        if prev_from != Some(from) {
            prev_from = Some(from);

            // Listing without specifying the spender.
            let allowances = env.icrc103_get_allowances_or_panic(from.owner, args.clone());
            check_allowances(allowances, idx, from.owner);

            // List from a smaller `from_account`. If the smaller `from_account` has a different owner
            // the result list is empty - we don't have any approvals for that owner.
            // If the smaller `from_account` has a different subaccount, the result is the same
            // as listing for current `from_account` - the smaller subaccount does not match any account we generated.
            args.from_account = Some(prev_account(&from));
            let allowances = env.icrc103_get_allowances_or_panic(from.owner, args.clone());
            if args.from_account.unwrap().owner == from.owner {
                check_allowances(allowances, idx, from.owner);
            } else {
                assert_eq!(allowances.len(), 0);
            }
            args.from_account = Some(from);
        }

        // Listing with spender specified, the current `approve_pair` is skipped.
        args.prev_spender = Some(spender);
        let allowances = env.icrc103_get_allowances_or_panic(from.owner, args.clone());
        check_allowances(allowances, idx + 1, from.owner);

        // Listing with smaller spender, the current `approve_pair` is included.
        args.prev_spender = Some(prev_account(&spender));
        let allowances = env.icrc103_get_allowances_or_panic(from.owner, args);
        check_allowances(allowances, idx, from.owner);
    }
}

// The test focuses on testing if the returned allowances have the correct
// values for all fields (from, spender, amount, expiration).
#[test]
pub fn test_allowance_listing_values() {
    let approver = account(1, None);
    let approver_sub = account(2, Some(2));
    let spender = account(3, None);
    let spender_sub = account(4, Some(3));

    let env = TestEnv::setup();
    let fee = env.icrc1_fee();

    env.deposit(approver, 100 * fee, None);
    env.deposit(approver_sub, 100 * fee, None);

    let default_approve_args = ApproveArgs {
        from_subaccount: None,
        spender,
        amount: Nat::from(1u64),
        expected_allowance: None,
        expires_at: None,
        fee: None,
        memo: None,
        created_at_time: None,
    };

    // Simplest possible approval.
    let approve_args = default_approve_args.clone();
    let block_index = env
        .icrc2_approve(approver.owner, approve_args)
        .expect("approve failed");
    assert_eq!(block_index, Nat::from(2u64));

    let now = env.nanos_since_epoch_u64();

    // Spender subaccount, expiration
    let expiration_far = Some(now + Duration::from_secs(3600).as_nanos() as u64);
    let mut approve_args = default_approve_args.clone();
    approve_args.spender = spender_sub;
    approve_args.amount = Nat::from(2u64);
    approve_args.expires_at = expiration_far;
    let block_index = env
        .icrc2_approve(approver.owner, approve_args)
        .expect("approve failed");
    assert_eq!(block_index, Nat::from(3u64));

    // From subaccount
    let mut approve_args = default_approve_args.clone();
    approve_args.from_subaccount = approver_sub.subaccount;
    approve_args.amount = Nat::from(3u64);
    let block_index = env
        .icrc2_approve(approver_sub.owner, approve_args)
        .expect("approve failed");
    assert_eq!(block_index, Nat::from(4u64));

    // From subaccount, spender subaccount, expiration
    let expiration_near = Some(now + Duration::from_secs(10).as_nanos() as u64);
    let mut approve_args = default_approve_args.clone(); //(spender_sub, 4);
    approve_args.spender = spender_sub;
    approve_args.amount = Nat::from(4u64);
    approve_args.from_subaccount = approver_sub.subaccount;
    approve_args.expires_at = expiration_near;
    let block_index = env
        .icrc2_approve(approver_sub.owner, approve_args)
        .expect("approve failed");
    assert_eq!(block_index, Nat::from(5u64));

    let mut args = GetAllowancesArgs {
        from_account: Some(approver),
        prev_spender: None,
        take: None,
    };

    let allowances = env.icrc103_get_allowances_or_panic(approver.owner, args.clone());
    assert_eq!(allowances.len(), 2);

    assert_eq!(allowances[0].from_account, approver);
    assert_eq!(allowances[0].to_spender, spender);
    assert_eq!(allowances[0].allowance, Nat::from(1u64));
    assert_eq!(allowances[0].expires_at, None);

    assert_eq!(allowances[1].from_account, approver);
    assert_eq!(allowances[1].to_spender, spender_sub);
    assert_eq!(allowances[1].allowance, Nat::from(2u64));
    assert_eq!(allowances[1].expires_at, expiration_far);

    args.take = Some(Nat::from(1u64));

    let allowances_take = env.icrc103_get_allowances_or_panic(approver.owner, args.clone());
    assert_eq!(allowances_take.len(), 1);
    assert_eq!(allowances_take[0], allowances[0]);

    let args = GetAllowancesArgs {
        from_account: Some(approver_sub),
        prev_spender: None,
        take: None,
    };

    // Here we additionally test listing approvals of another Principal.
    let allowances = env.icrc103_get_allowances_or_panic(approver.owner, args.clone());
    assert_eq!(allowances.len(), 2);

    assert_eq!(allowances[0].from_account, approver_sub);
    assert_eq!(allowances[0].to_spender, spender);
    assert_eq!(allowances[0].allowance, Nat::from(3u64));
    assert_eq!(allowances[0].expires_at, None);

    assert_eq!(allowances[1].from_account, approver_sub);
    assert_eq!(allowances[1].to_spender, spender_sub);
    assert_eq!(allowances[1].allowance, Nat::from(4u64));
    assert_eq!(allowances[1].expires_at, expiration_near);

    env.advance_time(Duration::from_secs(10));

    let allowances_later = env.icrc103_get_allowances_or_panic(approver.owner, args);
    assert_eq!(allowances_later.len(), 1);
    assert_eq!(allowances_later[0], allowances[0]);
}

// Test whether specifying None/DEFAULT_SUBACCOUNT does not affect the results.
#[test]
pub fn test_allowance_listing_subaccount() {
    let approver_none = Account {
        owner: Principal::from_slice(&[1u8]),
        subaccount: None,
    };
    let approver_default = Account {
        owner: Principal::from_slice(&[2u8]),
        subaccount: Some(*DEFAULT_SUBACCOUNT),
    };
    let spender_none = Account {
        owner: Principal::from_slice(&[3u8]),
        subaccount: None,
    };
    let spender_default = Account {
        owner: Principal::from_slice(&[3u8]),
        subaccount: Some(*DEFAULT_SUBACCOUNT),
    };

    let env = TestEnv::setup();
    let fee = env.icrc1_fee();

    env.deposit(approver_none, 100 * fee, None);
    env.deposit(approver_default, 100 * fee, None);

    let default_approve_args = ApproveArgs {
        from_subaccount: None,
        spender: spender_none,
        amount: Nat::from(1u64),
        expected_allowance: None,
        expires_at: None,
        fee: None,
        memo: None,
        created_at_time: None,
    };

    let approve_args = default_approve_args.clone();
    let block_index = env
        .icrc2_approve(approver_none.owner, approve_args)
        .expect("approve failed");
    assert_eq!(block_index, Nat::from(2u64));

    let mut approve_args = default_approve_args.clone(); //(spender_default, 1);
    approve_args.spender = spender_default;
    approve_args.from_subaccount = approver_default.subaccount;
    let block_index = env
        .icrc2_approve(approver_default.owner, approve_args)
        .expect("approve failed");
    assert_eq!(block_index, Nat::from(3u64));

    // Should return the allowance, if we specify `from_account` as when creating approval
    let args = GetAllowancesArgs {
        from_account: Some(approver_none),
        prev_spender: None,
        take: None,
    };
    let allowances = env.icrc103_get_allowances_or_panic(approver_none.owner, args.clone());
    assert_eq!(allowances.len(), 1);

    // Should return the allowance, if we specify `from_account` with explicit default subaccount.
    let mut approver_none_default = approver_none;
    approver_none_default.subaccount = Some(*DEFAULT_SUBACCOUNT);
    let args = GetAllowancesArgs {
        from_account: Some(approver_none_default),
        prev_spender: None,
        take: None,
    };
    let allowances = env.icrc103_get_allowances_or_panic(approver_none.owner, args.clone());
    assert_eq!(allowances.len(), 1);

    // Should filter out the allowance if subaccount is none
    let args = GetAllowancesArgs {
        from_account: Some(approver_none),
        prev_spender: Some(spender_none),
        take: None,
    };
    let allowances = env.icrc103_get_allowances_or_panic(approver_none.owner, args.clone());
    assert_eq!(allowances.len(), 0);

    // Should filter out the allowance if subaccount is default
    let args = GetAllowancesArgs {
        from_account: Some(approver_none),
        prev_spender: Some(spender_default),
        take: None,
    };
    let allowances = env.icrc103_get_allowances_or_panic(approver_none.owner, args.clone());
    assert_eq!(allowances.len(), 0);

    // Should return the allowance, if we specify `from_account` as when creating approval
    let args = GetAllowancesArgs {
        from_account: Some(approver_default),
        prev_spender: None,
        take: None,
    };
    let allowances = env.icrc103_get_allowances_or_panic(approver_default.owner, args.clone());
    assert_eq!(allowances.len(), 1);

    // Should return the allowance, if we specify `from_account` with none subaccount.
    let mut approver_default_none = approver_default;
    approver_default_none.subaccount = None;
    let args = GetAllowancesArgs {
        from_account: Some(approver_default_none),
        prev_spender: None,
        take: None,
    };
    let allowances = env.icrc103_get_allowances_or_panic(approver_default.owner, args);
    assert_eq!(allowances.len(), 1);
}

// The test focuses on testing various values for the `take` parameter.
#[test]
pub fn test_allowance_listing_take() {
    const MAX_RESULTS: usize = 500;
    const NUM_SPENDERS: usize = MAX_RESULTS + 1;

    let approver = account(1, None);

    let mut spenders = vec![];
    for i in 2..NUM_SPENDERS + 2 {
        spenders.push(account(i as u64, None));
    }
    assert_eq!(spenders.len(), NUM_SPENDERS);

    let env = TestEnv::setup();
    let fee = env.icrc1_fee();

    env.deposit(approver, 1_000_000 * fee, None);

    for spender in &spenders {
        let approve_args = ApproveArgs {
            from_subaccount: None,
            spender: *spender,
            amount: Nat::from(10u64),
            expected_allowance: None,
            expires_at: None,
            fee: Some(Nat::from(FEE)),
            memo: None,
            created_at_time: None,
        };
        let _ = env
            .icrc2_approve(approver.owner, approve_args)
            .expect("approve failed");
    }

    let mut args = GetAllowancesArgs {
        from_account: Some(approver),
        prev_spender: None,
        take: None,
    };

    let allowances = env.icrc103_get_allowances_or_panic(approver.owner, args.clone());
    assert_eq!(allowances.len(), MAX_RESULTS);

    args.take = Some(Nat::from(0u64));
    let allowances = env.icrc103_get_allowances_or_panic(approver.owner, args.clone());
    assert_eq!(allowances.len(), 0);

    args.take = Some(Nat::from(5u64));
    let allowances = env.icrc103_get_allowances_or_panic(approver.owner, args.clone());
    assert_eq!(allowances.len(), 5);

    args.take = Some(Nat::from(u64::MAX));
    let allowances = env.icrc103_get_allowances_or_panic(approver.owner, args.clone());
    assert_eq!(allowances.len(), MAX_RESULTS);

    args.take = Some(Nat::from(
        BigUint::parse_bytes(b"1000000000000000000000000000000000000000", 10).unwrap(),
    ));
    assert!(args.take.clone().unwrap().0.to_u64().is_none());
    let allowances = env.icrc103_get_allowances_or_panic(approver.owner, args);
    assert_eq!(allowances.len(), MAX_RESULTS);
}

#[derive(Clone, Copy)]
enum ShouldSetCreatedAtTime {
    SetCreatedAtTime,
    DontSetCreatedAtTime,
}

impl ShouldSetCreatedAtTime {
    fn then_some<T>(self, t: T) -> Option<T> {
        match self {
            Self::SetCreatedAtTime => Some(t),
            Self::DontSetCreatedAtTime => None,
        }
    }
}

#[derive(Clone, Copy)]
enum ShouldSetFee {
    SetFee,
    DontSetFee,
}

impl ShouldSetFee {
    fn then_some<T>(self, t: T) -> Option<T> {
        match self {
            Self::SetFee => Some(t),
            Self::DontSetFee => None,
        }
    }
}

#[derive(Clone, Copy)]
enum ShouldSetMemo {
    SetMemo,
    DontSetMemo,
}

impl ShouldSetMemo {
    fn then_some<T>(self, t: T) -> Option<T> {
        match self {
            Self::SetMemo => Some(t),
            Self::DontSetMemo => None,
        }
    }
}

#[derive(Clone, Copy)]
enum ShouldSetExpectedAllowance {
    SetExpectedAllowance,
    DontSetExpectedAllowance,
}

impl ShouldSetExpectedAllowance {
    fn then_some<T>(self, t: T) -> Option<T> {
        match self {
            Self::SetExpectedAllowance => Some(t),
            Self::DontSetExpectedAllowance => None,
        }
    }
}

#[derive(Clone, Copy)]
enum ShouldSetExpiresAt {
    SetExpiresAt,
    DontSetExpiresAt,
}

impl ShouldSetExpiresAt {
    fn then_some<T>(self, t: T) -> Option<T> {
        match self {
            Self::SetExpiresAt => Some(t),
            Self::DontSetExpiresAt => None,
        }
    }
}

fn test_icrc1_transfer_ok_with_params(
    env: &TestEnv,
    set_created_at_time: ShouldSetCreatedAtTime,
    set_fee: ShouldSetFee,
    set_memo: ShouldSetMemo,
) {
    // Make a transfer that must succeed and check the Ledger has changed
    // accordingly.

    let account_from = account(1, None);
    let account_to = account(2, None);
    let amount = 1_000_000_000;
    let fee = env.icrc1_fee();
    // if args_*_should_be_set is true then that field in the transfer argument
    // must be set to a valid value
    let args_created_at_time = set_created_at_time.then_some(env.nanos_since_epoch_u64());
    let args_fee = set_fee.then_some(fee);
    let args_memo = set_memo.then_some(Memo::from(vec![1u8; 32]));

    let _deposit_res = env.deposit(account_from, amount + 2 * fee, None);

    // state that should change after the transfer is executed
    let account_from_balance_before = env.icrc1_balance_of(account_from);
    let account_to_balance_before = env.icrc1_balance_of(account_to);
    let total_supply_before = env.icrc1_total_supply();
    let mut expected_blocks = env.get_all_blocks();

    let args = TransferArgs {
        from_subaccount: account_from.subaccount,
        to: account_to,
        amount: Nat::from(amount),
        fee: args_fee.map(Nat::from),
        created_at_time: args_created_at_time,
        memo: args_memo.clone(),
    };
    let block_index = env.icrc1_transfer_or_trap(account_from.owner, args);

    assert_eq!(
        env.icrc1_balance_of(account_from),
        account_from_balance_before - amount - fee,
    );
    assert_eq!(
        env.icrc1_balance_of(account_to),
        account_to_balance_before + amount,
    );
    assert_eq!(env.icrc1_total_supply(), total_supply_before - fee,);

    let expected_new_block = Block {
        transaction: Transaction {
            operation: Operation::Transfer {
                from: account_from,
                to: account_to,
                spender: None,
                amount,
                fee: args_fee,
            },
            created_at_time: args_created_at_time,
            memo: args_memo,
        },
        timestamp: env.nanos_since_epoch_u64(),
        phash: Some(env.get_block(block_index - 1u8).hash()),
        effective_fee: args_fee.xor(Some(fee)),
    };
    expected_blocks.push(expected_new_block);
    assert_vec_display_eq(expected_blocks, env.get_all_blocks());
}

fn test_icrc1_transfer_ok_without_created_at_time(env: &TestEnv) {
    use ShouldSetCreatedAtTime::*;
    use ShouldSetFee::*;
    use ShouldSetMemo::*;

    // This function is safe to be called multiple times because
    // the transactions it creates are not marked for deduplication.
    test_icrc1_transfer_ok_with_params(env, DontSetCreatedAtTime, DontSetFee, DontSetMemo);
    test_icrc1_transfer_ok_with_params(env, DontSetCreatedAtTime, SetFee, DontSetMemo);
    test_icrc1_transfer_ok_with_params(env, DontSetCreatedAtTime, DontSetFee, SetMemo);
    test_icrc1_transfer_ok_with_params(env, DontSetCreatedAtTime, SetFee, SetMemo);
}

fn test_icrc1_transfer_ok_with_created_at_time(env: &TestEnv) {
    use ShouldSetCreatedAtTime::*;
    use ShouldSetFee::*;
    use ShouldSetMemo::*;

    // Like [test_icrc1_transfer_ok_without_created_at_time] but
    // created_at_time is set so this function can be called once
    // per deduplication window.
    test_icrc1_transfer_ok_with_params(env, SetCreatedAtTime, DontSetFee, DontSetMemo);
    test_icrc1_transfer_ok_with_params(env, SetCreatedAtTime, SetFee, DontSetMemo);
    test_icrc1_transfer_ok_with_params(env, SetCreatedAtTime, DontSetFee, SetMemo);
    test_icrc1_transfer_ok_with_params(env, SetCreatedAtTime, SetFee, SetMemo);
}

#[test]
fn test_icrc1_transfer() {
    let env = TestEnv::setup();

    test_icrc1_transfer_ok_without_created_at_time(&env);
    // The test should be able to run many times with no
    // issues as it doesn't mark the transasctions for deduplication.
    test_icrc1_transfer_ok_without_created_at_time(&env);
    // Test icrc1_transfer with created_at_time set.
    test_icrc1_transfer_ok_with_created_at_time(&env);
    // Move time forward to change the transaction created_at_time
    env.state_machine.advance_time(Duration::from_secs(1));
    // Submit again transactions. created_at_time has changed which
    // means no deduplication should happen
    test_icrc1_transfer_ok_with_created_at_time(&env);
}

#[test]
fn test_icrc1_transfer_failures() {
    let env = TestEnv::setup();

    test_icrc1_transfer_invalid_arg(&env);
    test_icrc1_transfer_insufficient_funds(&env);
    test_icrc1_transfer_duplicate(&env);
}

fn test_icrc1_transfer_denied_from(env: &TestEnv) {
    let account_to = account(3, None);
    let account_to_balance = env.icrc1_balance_of(account_to);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();
    let owner = Principal::management_canister();
    for subaccount in [None, Some([0; 32])] {
        let args = TransferArgs {
            from_subaccount: subaccount,
            to: account_to,
            amount: Nat::from(0u8),
            fee: None,
            created_at_time: None,
            memo: None,
        };
        let expected_error = TransferError::GenericError {
            error_code: Nat::from(DENIED_OWNER),
            message: format!(
                "Owner of the account {} cannot be part of transactions",
                Account { owner, subaccount },
            ),
        };
        assert_eq!(Err(expected_error), env.icrc1_transfer(owner, args),);
    }
    assert_eq!(account_to_balance, env.icrc1_balance_of(account_to));
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc1_transfer_denied_to(env: &TestEnv) {
    let account_from = account(3, None);
    let account_from_balance = env.icrc1_balance_of(account_from);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();
    let owner = Principal::management_canister();
    for subaccount in [None, Some([0; 32])] {
        let account_to = Account { owner, subaccount };
        let args = TransferArgs {
            from_subaccount: account_from.subaccount,
            to: account_to,
            amount: Nat::from(0u8),
            fee: None,
            created_at_time: None,
            memo: None,
        };
        let expected_error = TransferError::GenericError {
            error_code: Nat::from(DENIED_OWNER),
            message: format!(
                "Owner of the account {} cannot be part of transactions",
                account_to,
            ),
        };
        assert_eq!(Err(expected_error), env.icrc1_transfer(owner, args),);
    }

    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc1_transfer_invalid_fee(env: &TestEnv) {
    let account_to = account(2, None);
    let account_from = account(3, None);
    let fee = env.icrc1_fee();

    // deposit enough funds to account_to such that the transaction
    // should happen if correct
    let _deposit_index = env.deposit(account_from, 2 * fee, None);

    let account_to_balance = env.icrc1_balance_of(account_to);
    let account_from_balance = env.icrc1_balance_of(account_from);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();

    for bad_fee in [0, fee - 1, fee + 1, u128::MAX] {
        let args = TransferArgs {
            from_subaccount: account_from.subaccount,
            to: account_to,
            amount: Nat::from(0u8),
            fee: Some(Nat::from(bad_fee)),
            created_at_time: None,
            memo: None,
        };
        assert_eq!(
            Err(TransferError::BadFee {
                expected_fee: Nat::from(fee)
            }),
            env.icrc1_transfer(account_from.owner, args),
        );
    }
    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(account_to_balance, env.icrc1_balance_of(account_to));
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc1_transfer_too_old(env: &TestEnv) {
    // A transaction is too old if its created_at_time is
    // before ledger_time - TRANSACTION_WINDOW - PERMITTED_DRIFT
    let ledger_time = env.nanos_since_epoch_u64();
    let too_old_created_at_time = Duration::from_nanos(ledger_time)
        - config::TRANSACTION_WINDOW
        - config::PERMITTED_DRIFT
        - Duration::from_nanos(1);

    let account_to = account(2, None);
    let account_from = account(3, None);

    // deposit enough funds to account_to such that the transaction
    // would be accepted if created_at_time was correct
    let _deposit_index = env.deposit(account_from, 2 * env.icrc1_fee(), None);

    let account_to_balance = env.icrc1_balance_of(account_to);
    let account_from_balance = env.icrc1_balance_of(account_from);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();

    let args = TransferArgs {
        from_subaccount: account_from.subaccount,
        to: account_to,
        amount: Nat::from(0u8),
        fee: None,
        created_at_time: Some(too_old_created_at_time.as_nanos() as u64),
        memo: None,
    };
    assert_eq!(
        Err(TransferError::TooOld),
        env.icrc1_transfer(account_from.owner, args),
    );
    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(account_to_balance, env.icrc1_balance_of(account_to));
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc1_transfer_in_the_future(env: &TestEnv) {
    // A transaction is in the future if its created_at_time is
    // after ledger_time + PERMITTED_DRIFT
    let ledger_time = env.nanos_since_epoch_u64();
    let in_the_future_created_at_time =
        Duration::from_nanos(ledger_time) + config::PERMITTED_DRIFT + Duration::from_nanos(1);

    let account_to = account(2, None);
    let account_from = account(3, None);

    // deposit enough funds to account_to such that the transaction
    // would be accepted if created_at_time was correct
    let _deposit_index = env.deposit(account_from, 2 * env.icrc1_fee(), None);

    let account_to_balance = env.icrc1_balance_of(account_to);
    let account_from_balance = env.icrc1_balance_of(account_from);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();

    let args = TransferArgs {
        from_subaccount: account_from.subaccount,
        to: account_to,
        amount: Nat::from(0u8),
        fee: None,
        created_at_time: Some(in_the_future_created_at_time.as_nanos() as u64),
        memo: None,
    };
    assert_eq!(
        Err(TransferError::CreatedInFuture { ledger_time }),
        env.icrc1_transfer(account_from.owner, args),
    );
    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(account_to_balance, env.icrc1_balance_of(account_to));
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc1_transfer_invalid_arg(env: &TestEnv) {
    test_icrc1_transfer_denied_from(env);
    test_icrc1_transfer_denied_to(env);
    test_icrc1_transfer_invalid_fee(env);
    test_icrc1_transfer_too_old(env);
    test_icrc1_transfer_in_the_future(env);
    // memo is tested by [test_icrc1_transfer_invalid_memo]
}

fn test_icrc1_transfer_insufficient_funds_with_params(
    env: &TestEnv,
    set_created_at_time: ShouldSetCreatedAtTime,
    set_fee: ShouldSetFee,
    set_memo: ShouldSetMemo,
) {
    let account_from = account(1, None);
    let account_to = account(2, None);
    let fee = env.icrc1_fee();

    // Deposit so that account_from has at least the fee in its account
    let _deposit_index = env.deposit(account_from, 2 * fee, None);
    let account_from_balance = env.icrc1_balance_of(account_from);
    let account_to_balance = env.icrc1_balance_of(account_to);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();

    // Try different amounts that should fail, specifically:
    for amount in [
        // 1 cycles more than what account_from can transfer =>
        // fails because the user cannot pay the fee
        account_from_balance - fee + 1,
        // 1 cycles less than the account_from balance =>
        // fails because the user cannot pay the fee
        account_from_balance - 1,
        // 1 cycles more than the account_from balance =>
        // fails because the user doesn't have enough cycles
        account_from_balance + 1,
    ] {
        let args = TransferArgs {
            from_subaccount: account_from.subaccount,
            to: account_to,
            // Amount is 1 cycle more than what account_from can transfer
            amount: Nat::from(amount),
            fee: set_fee.then_some(Nat::from(fee)),
            created_at_time: set_created_at_time.then_some(env.nanos_since_epoch_u64()),
            memo: set_memo.then_some(Memo::from(vec![2; 32])),
        };
        assert_eq!(
            Err(TransferError::InsufficientFunds {
                balance: Nat::from(account_from_balance)
            }),
            env.icrc1_transfer(account_from.owner, args)
        );
        assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
        assert_eq!(account_to_balance, env.icrc1_balance_of(account_to));
        assert_eq!(total_supply, env.icrc1_total_supply());
        assert_vec_display_eq(&blocks, env.get_all_blocks());
    }
}

fn test_icrc1_transfer_insufficient_funds(env: &TestEnv) {
    use ShouldSetCreatedAtTime::*;
    use ShouldSetFee::*;
    use ShouldSetMemo::*;

    // test_icrc1_transfer_insufficient_funds_with_params takes in input 3 booleans
    // set_created_at_time, set_fee and set_memo.
    // Try all the permutations.
    test_icrc1_transfer_insufficient_funds_with_params(
        env,
        DontSetCreatedAtTime,
        DontSetFee,
        DontSetMemo,
    );
    test_icrc1_transfer_insufficient_funds_with_params(
        env,
        DontSetCreatedAtTime,
        SetFee,
        DontSetMemo,
    );
    test_icrc1_transfer_insufficient_funds_with_params(
        env,
        DontSetCreatedAtTime,
        DontSetFee,
        SetMemo,
    );
    test_icrc1_transfer_insufficient_funds_with_params(env, DontSetCreatedAtTime, SetFee, SetMemo);
    test_icrc1_transfer_insufficient_funds_with_params(
        env,
        SetCreatedAtTime,
        DontSetFee,
        DontSetMemo,
    );
    test_icrc1_transfer_insufficient_funds_with_params(env, SetCreatedAtTime, SetFee, DontSetMemo);
    test_icrc1_transfer_insufficient_funds_with_params(env, SetCreatedAtTime, SetFee, DontSetMemo);
    test_icrc1_transfer_insufficient_funds_with_params(env, SetCreatedAtTime, SetFee, SetMemo);
}

fn test_icrc1_transfer_duplicate_with_params(
    env: &TestEnv,
    set_fee: ShouldSetFee,
    set_memo: ShouldSetMemo,
    has_fee_for_second_transfer: bool,
) {
    let account_from = account(1, None);
    let account_to = account(2, None);
    let fee = env.icrc1_fee();
    let ledger_time = Duration::from_nanos(env.nanos_since_epoch_u64());

    // Try different valid non-optional created_at_time
    for created_at_time in [
        // 1 nanosecond before being too old
        ledger_time - config::TRANSACTION_WINDOW - config::PERMITTED_DRIFT,
        // 1 nanosecond before ledger_time
        ledger_time - Duration::from_nanos(1),
        // 1 nanosecond after ledger_time
        ledger_time + Duration::from_nanos(1),
        // 1 nanosecond before being in the future
        ledger_time + config::PERMITTED_DRIFT,
    ] {
        // Deposit so that account_from has enough fee to make one
        // or two transfers. Note that in case account_from has
        // only one fee then the second transfer should return
        // a duplicate error and not an insufficient funds error
        let deposit_amount = if has_fee_for_second_transfer {
            2 * fee
        } else {
            fee
        };
        let _deposit_index = env.deposit(account_from, deposit_amount + fee, None);

        let args = TransferArgs {
            from_subaccount: account_from.subaccount,
            to: account_to,
            // Amount is 1 cycle more than what account_from can transfer
            amount: Nat::from(0u8),
            fee: set_fee.then_some(Nat::from(fee)),
            created_at_time: Some(created_at_time.as_nanos() as u64),
            memo: set_memo.then_some(Memo::from(vec![3; 32])),
        };
        let block_index = env.icrc1_transfer_or_trap(account_from.owner, args.clone());

        let account_from_balance = env.icrc1_balance_of(account_from);
        let account_to_balance = env.icrc1_balance_of(account_to);
        let total_supply = env.icrc1_total_supply();
        let blocks = env.get_all_blocks();

        assert_eq!(
            Err(TransferError::Duplicate {
                duplicate_of: block_index
            }),
            env.icrc1_transfer(account_from.owner, args),
        );

        assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
        assert_eq!(account_to_balance, env.icrc1_balance_of(account_to));
        assert_eq!(total_supply, env.icrc1_total_supply());
        assert_vec_display_eq(&blocks, env.get_all_blocks());
    }
}

fn test_icrc1_transfer_duplicate(env: &TestEnv) {
    use ShouldSetFee::*;
    use ShouldSetMemo::*;

    test_icrc1_transfer_duplicate_with_params(env, DontSetFee, DontSetMemo, false);
    test_icrc1_transfer_duplicate_with_params(env, SetFee, DontSetMemo, false);
    test_icrc1_transfer_duplicate_with_params(env, DontSetFee, SetMemo, false);
    test_icrc1_transfer_duplicate_with_params(env, SetFee, SetMemo, false);
    // Change the ledger time to avoid duplicates between the first
    // four tests and the next four tests.
    env.state_machine.advance_time(Duration::from_nanos(1));
    test_icrc1_transfer_duplicate_with_params(env, DontSetFee, DontSetMemo, true);
    test_icrc1_transfer_duplicate_with_params(env, SetFee, DontSetMemo, true);
    test_icrc1_transfer_duplicate_with_params(env, DontSetFee, SetMemo, true);
    test_icrc1_transfer_duplicate_with_params(env, SetFee, SetMemo, true);
}

fn test_icrc2_approve_ok_with_params(
    env: &TestEnv,
    set_created_at_time: ShouldSetCreatedAtTime,
    set_fee: ShouldSetFee,
    set_memo: ShouldSetMemo,
    set_expected_allowance: ShouldSetExpectedAllowance,
    set_expires_at: ShouldSetExpiresAt,
) {
    // Make a transfer that must succeed and check the Ledger has changed
    // accordingly.

    let account_from = account(1, None);
    let account_spender = account(2, None);
    let amount = 1;
    let fee = env.icrc1_fee();
    // if args_*_should_be_set is true then that field in the transfer argument
    // must be set to a valid value
    let args_created_at_time = set_created_at_time.then_some(env.nanos_since_epoch_u64());
    let args_fee = set_fee.then_some(fee);
    let args_memo = set_memo.then_some(Memo::from(vec![1u8; 32]));
    let args_expected_allowance = set_expected_allowance.then_some(
        env.icrc2_allowance(account_from, account_spender)
            .allowance
            .0
            .to_u128()
            .unwrap(),
    );
    let args_expires_at = set_expires_at.then_some(
        env.nanos_since_epoch_u64() + Duration::from_secs(24 * 60 * 60).as_nanos() as u64,
    );

    let _deposit_res = env.deposit(account_from, amount + 2 * fee, None);

    // state that should change after the transfer is executed
    let account_from_balance_before = env.icrc1_balance_of(account_from);
    let account_to_balance_before = env.icrc1_balance_of(account_spender);
    let total_supply_before = env.icrc1_total_supply();
    let mut expected_blocks = env.get_all_blocks();

    let args = ApproveArgs {
        from_subaccount: account_from.subaccount,
        spender: account_spender,
        amount: Nat::from(amount),
        expected_allowance: args_expected_allowance.map(Nat::from),
        expires_at: args_expires_at,
        fee: args_fee.map(Nat::from),
        memo: args_memo.clone(),
        created_at_time: args_created_at_time,
    };
    let block_index = env.icrc2_approve_or_trap(account_from.owner, args);

    assert_eq!(
        env.icrc1_balance_of(account_from),
        account_from_balance_before - fee,
    );
    assert_eq!(
        env.icrc1_balance_of(account_spender),
        account_to_balance_before,
    );
    assert_eq!(env.icrc1_total_supply(), total_supply_before - fee,);
    assert_eq!(
        env.icrc2_allowance(account_from, account_spender),
        Allowance {
            allowance: Nat::from(1u8),
            expires_at: args_expires_at,
        }
    );

    let expected_new_block = Block {
        transaction: Transaction {
            operation: Operation::Approve {
                from: account_from,
                spender: account_spender,
                amount,
                expected_allowance: args_expected_allowance,
                expires_at: args_expires_at,
                fee: args_fee,
            },
            created_at_time: args_created_at_time,
            memo: args_memo,
        },
        timestamp: env.nanos_since_epoch_u64(),
        phash: Some(env.get_block(block_index - 1u8).hash()),
        effective_fee: args_fee.xor(Some(fee)),
    };
    expected_blocks.push(expected_new_block);
    assert_vec_display_eq(expected_blocks, env.get_all_blocks());
}

fn test_icrc2_approve_ok_without_created_at_time(env: &TestEnv) {
    // This function is safe to be called multiple times because
    // the transactions it creates are not marked for deduplication.

    use ShouldSetCreatedAtTime::*;
    use ShouldSetExpectedAllowance::*;
    use ShouldSetExpiresAt::*;
    use ShouldSetFee::*;
    use ShouldSetMemo::*;

    for should_set_expected_allowance in [DontSetExpectedAllowance, SetExpectedAllowance] {
        for should_set_expires_at in [DontSetExpiresAt, SetExpiresAt] {
            for should_set_fee in [DontSetFee, SetFee] {
                for should_set_memo in [DontSetMemo, SetMemo] {
                    test_icrc2_approve_ok_with_params(
                        env,
                        DontSetCreatedAtTime,
                        should_set_fee,
                        should_set_memo,
                        should_set_expected_allowance,
                        should_set_expires_at,
                    )
                }
            }
        }
    }
}

fn test_icrc2_approve_ok_with_created_at_time(env: &TestEnv) {
    // This function works like [test_icrc2_approve_ok_without_created_at_time]
    // except that it sets the created_at_time and therefore it is not safe
    // to call multiple times unless the time on the Ledger, which is used as
    // created_at_time, has changed.

    use ShouldSetCreatedAtTime::*;
    use ShouldSetExpectedAllowance::*;
    use ShouldSetExpiresAt::*;
    use ShouldSetFee::*;
    use ShouldSetMemo::*;

    for should_set_expected_allowance in [DontSetExpectedAllowance, SetExpectedAllowance] {
        for should_set_expires_at in [DontSetExpiresAt, SetExpiresAt] {
            for should_set_fee in [DontSetFee, SetFee] {
                for should_set_memo in [DontSetMemo, SetMemo] {
                    test_icrc2_approve_ok_with_params(
                        env,
                        SetCreatedAtTime,
                        should_set_fee,
                        should_set_memo,
                        should_set_expected_allowance,
                        should_set_expires_at,
                    )
                }
            }
        }
    }
}

fn test_icrc2_approve_denied_from(env: &TestEnv) {
    let account_spender = account(3, None);
    let account_spender_balance = env.icrc1_balance_of(account_spender);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();
    let owner = Principal::management_canister();
    for subaccount in [None, Some([0; 32])] {
        let args = ApproveArgs {
            from_subaccount: subaccount,
            spender: account_spender,
            amount: Nat::from(0u8),
            fee: None,
            created_at_time: None,
            memo: None,
            expected_allowance: None,
            expires_at: None,
        };
        let expected_error = ApproveError::GenericError {
            error_code: Nat::from(DENIED_OWNER),
            message: format!(
                "Owner of the account {} cannot be part of approvals",
                Account { owner, subaccount },
            ),
        };
        assert_eq!(Err(expected_error), env.icrc2_approve(owner, args),);
    }

    assert_eq!(
        account_spender_balance,
        env.icrc1_balance_of(account_spender)
    );
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc2_approve_denied_spender(env: &TestEnv) {
    let account_from = account(3, None);
    let account_from_balance = env.icrc1_balance_of(account_from);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();
    let owner = Principal::management_canister();
    for subaccount in [None, Some([0; 32])] {
        let spender = Account { owner, subaccount };
        let args = ApproveArgs {
            from_subaccount: account_from.subaccount,
            spender,
            amount: Nat::from(0u8),
            fee: None,
            created_at_time: None,
            memo: None,
            expected_allowance: None,
            expires_at: None,
        };
        let expected_error = ApproveError::GenericError {
            error_code: Nat::from(DENIED_OWNER),
            message: format!(
                "Owner of the account {} cannot be part of approvals",
                Account { owner, subaccount },
            ),
        };
        assert_eq!(
            Err(expected_error),
            env.icrc2_approve(account_from.owner, args),
        );
    }
    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc2_approve_invalid_fee(env: &TestEnv) {
    let fee = env.icrc1_fee();

    for bad_fee in [0, fee - 1, fee + 1, u128::MAX] {
        assert_icrc2_approve_failure(
            env,
            |_, _| ApproveError::BadFee {
                expected_fee: Nat::from(fee),
            },
            |account_from, account_spender| ApproveArgs {
                from_subaccount: account_from.subaccount,
                spender: account_spender,
                amount: Nat::from(0u8),
                fee: Some(Nat::from(bad_fee)),
                created_at_time: None,
                memo: None,
                expected_allowance: None,
                expires_at: None,
            },
        );
    }
}

fn test_icrc2_approve_too_old(env: &TestEnv) {
    // A transaction is too old if its created_at_time is
    // before ledger_time - TRANSACTION_WINDOW - PERMITTED_DRIFT
    let ledger_time = env.nanos_since_epoch_u64();
    let too_old_created_at_time = Duration::from_nanos(ledger_time)
        - config::TRANSACTION_WINDOW
        - config::PERMITTED_DRIFT
        - Duration::from_nanos(1);

    assert_icrc2_approve_failure(
        env,
        |_, _| ApproveError::TooOld,
        |account_from, account_spender| ApproveArgs {
            from_subaccount: account_from.subaccount,
            spender: account_spender,
            amount: Nat::from(0u8),
            fee: None,
            created_at_time: Some(too_old_created_at_time.as_nanos() as u64),
            memo: None,
            expected_allowance: None,
            expires_at: None,
        },
    )
}

fn test_icrc2_approve_in_the_future(env: &TestEnv) {
    // A transaction is in the future if its created_at_time is
    // after ledger_time + PERMITTED_DRIFT
    let ledger_time = env.nanos_since_epoch_u64();
    let in_the_future_created_at_time =
        Duration::from_nanos(ledger_time) + config::PERMITTED_DRIFT + Duration::from_nanos(1);

    assert_icrc2_approve_failure(
        env,
        |_, _| ApproveError::CreatedInFuture { ledger_time },
        |account_from, account_spender| ApproveArgs {
            from_subaccount: account_from.subaccount,
            spender: account_spender,
            amount: Nat::from(0u8),
            fee: None,
            created_at_time: Some(in_the_future_created_at_time.as_nanos() as u64),
            memo: None,
            expected_allowance: None,
            expires_at: None,
        },
    );
}

fn test_icrc2_approve_allowance_changed(env: &TestEnv) {
    assert_icrc2_approve_failure(
        env,
        |account_from, account_spender| {
            let current_allowance = env.icrc2_allowance(account_from, account_spender).allowance;
            ApproveError::AllowanceChanged { current_allowance }
        },
        |account_from, account_spender| {
            let current_allowance = env.icrc2_allowance(account_from, account_spender).allowance;
            let expected_allowance = if current_allowance == u128::MAX {
                Nat::from(0u8)
            } else {
                current_allowance + 1u8
            };
            ApproveArgs {
                from_subaccount: account_from.subaccount,
                spender: account_spender,
                amount: Nat::from(1u8),
                expected_allowance: Some(expected_allowance),
                expires_at: None,
                fee: None,
                memo: None,
                created_at_time: None,
            }
        },
    )
}

fn test_icrc2_approve_expired(env: &TestEnv) {
    let ledger_time = env.nanos_since_epoch_u64();
    // anything before or equals to ledger_time should fail.
    for expires_at in [0, ledger_time - 1, ledger_time] {
        assert_icrc2_approve_failure(
            env,
            |_, _| ApproveError::Expired { ledger_time },
            |account_from, account_spender| ApproveArgs {
                from_subaccount: account_from.subaccount,
                spender: account_spender,
                amount: Nat::from(1u8),
                expected_allowance: None,
                expires_at: Some(expires_at),
                fee: None,
                memo: None,
                created_at_time: None,
            },
        )
    }
}

#[track_caller]
fn assert_icrc2_approve_failure<F, G>(env: &TestEnv, expected_error: G, f: F)
where
    G: FnOnce(/* from: */ Account, /* spender: */ Account) -> ApproveError,
    F: FnOnce(/* from: */ Account, /* spender: */ Account) -> ApproveArgs,
{
    let account_spender = account(2, None);
    let account_from = account(3, None);

    // deposit enough funds to account_to such that the transaction
    // would be accepted if created_at_time was correct
    let _deposit_index = env.deposit(account_from, 2 * env.icrc1_fee(), None);

    let account_spender_balance = env.icrc1_balance_of(account_spender);
    let account_from_balance = env.icrc1_balance_of(account_from);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();

    let expected_error = expected_error(account_from, account_spender);
    let args = f(account_from, account_spender);
    assert_eq!(
        Err(expected_error),
        env.icrc2_approve(account_from.owner, args)
    );
    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(
        account_spender_balance,
        env.icrc1_balance_of(account_spender)
    );
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc2_approve_invalid_arg(env: &TestEnv) {
    test_icrc2_approve_denied_from(env);
    test_icrc2_approve_denied_spender(env);
    // self approve is tested by [test_approve_self]
    test_icrc2_approve_invalid_fee(env);
    test_icrc2_approve_too_old(env);
    test_icrc2_approve_in_the_future(env);
    test_icrc2_approve_allowance_changed(env);
    test_icrc2_approve_expired(env);
}

fn test_icrc2_approve_insufficient_funds_with_params(
    env: &TestEnv,
    set_created_at_time: ShouldSetCreatedAtTime,
    set_fee: ShouldSetFee,
    set_memo: ShouldSetMemo,
    set_expected_allowance: ShouldSetExpectedAllowance,
    set_expires_at: ShouldSetExpiresAt,
) {
    let account_from = account(1, None);
    let account_spender = account(2, None);
    let fee = env.icrc1_fee();

    let account_from_balance = env.icrc1_balance_of(account_from);
    // remove cycles from account_from so that it can pay the approve fee
    if account_from_balance >= fee {
        let _block_index = env.icrc1_transfer_or_trap(
            account_from.owner,
            TransferArgs {
                from_subaccount: None,
                to: account_spender,
                amount: Nat::from(account_from_balance - fee + 1),
                fee: None,
                created_at_time: None,
                memo: None,
            },
        );
    }
    let account_spender_balance = env.icrc1_balance_of(account_spender);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();

    let current_allowance = env.icrc2_allowance(account_from, account_spender).allowance;
    let args = ApproveArgs {
        from_subaccount: account_from.subaccount,
        spender: account_spender,
        amount: Nat::from(1u8),
        fee: set_fee.then_some(Nat::from(fee)),
        created_at_time: set_created_at_time.then_some(env.nanos_since_epoch_u64()),
        memo: set_memo.then_some(Memo::from(vec![2; 32])),
        expected_allowance: set_expected_allowance.then_some(current_allowance),
        expires_at: set_expires_at.then_some(env.nanos_since_epoch_u64() + 1),
    };
    assert_eq!(
        Err(ApproveError::InsufficientFunds {
            balance: Nat::from(account_from_balance)
        }),
        env.icrc2_approve(account_from.owner, args)
    );
    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(
        account_spender_balance,
        env.icrc1_balance_of(account_spender)
    );
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc2_approve_insufficient_funds(env: &TestEnv) {
    use ShouldSetCreatedAtTime::*;
    use ShouldSetExpectedAllowance::*;
    use ShouldSetExpiresAt::*;
    use ShouldSetFee::*;
    use ShouldSetMemo::*;

    for set_created_at_time in [DontSetCreatedAtTime, SetCreatedAtTime] {
        for set_fee in [DontSetFee, SetFee] {
            for set_memo in [DontSetMemo, SetMemo] {
                for set_expected_allowance in [DontSetExpectedAllowance, SetExpectedAllowance] {
                    for set_expires_at in [DontSetExpiresAt, SetExpiresAt] {
                        test_icrc2_approve_insufficient_funds_with_params(
                            env,
                            set_created_at_time,
                            set_fee,
                            set_memo,
                            set_expected_allowance,
                            set_expires_at,
                        );
                    }
                }
            }
        }
    }
}

fn test_icrc2_approve_duplicate_with_params(
    env: &TestEnv,
    set_fee: ShouldSetFee,
    set_memo: ShouldSetMemo,
    set_expected_allowance: ShouldSetExpectedAllowance,
    set_expires_at: ShouldSetExpiresAt,
) {
    let account_from = account(1, None);
    let account_spender = account(2, None);
    let fee = env.icrc1_fee();

    // deposit enough funds to account_from so that two approves
    // could go through
    let _deposit_index = env.deposit(account_from, 3 * fee, None);

    let current_allowance = env.icrc2_allowance(account_from, account_spender).allowance;
    let args = ApproveArgs {
        from_subaccount: account_from.subaccount,
        spender: account_spender,
        amount: Nat::from(1u8),
        fee: set_fee.then_some(Nat::from(fee)),
        created_at_time: Some(env.nanos_since_epoch_u64()),
        memo: set_memo.then_some(Memo::from(vec![2; 32])),
        expected_allowance: set_expected_allowance.then_some(current_allowance),
        expires_at: set_expires_at.then_some(env.nanos_since_epoch_u64() + 1),
    };
    let approve_res = env.icrc2_approve_or_trap(account_from.owner, args.clone());

    let account_from_balance = env.icrc1_balance_of(account_from);
    let account_spender_balance = env.icrc1_balance_of(account_spender);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();

    assert_eq!(
        Err(ApproveError::Duplicate {
            duplicate_of: approve_res
        }),
        env.icrc2_approve(account_from.owner, args),
    );
    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(
        account_spender_balance,
        env.icrc1_balance_of(account_spender)
    );
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc2_approve_duplicate(env: &TestEnv) {
    use ShouldSetExpectedAllowance::*;
    use ShouldSetExpiresAt::*;
    use ShouldSetFee::*;
    use ShouldSetMemo::*;

    for set_fee in [DontSetFee, SetFee] {
        for set_memo in [DontSetMemo, SetMemo] {
            for set_expected_allowance in [DontSetExpectedAllowance, SetExpectedAllowance] {
                for set_expires_at in [DontSetExpiresAt, SetExpiresAt] {
                    test_icrc2_approve_duplicate_with_params(
                        env,
                        set_fee,
                        set_memo,
                        set_expected_allowance,
                        set_expires_at,
                    );
                }
            }
        }
    }
}

#[test]
fn test_icrc2_approve() {
    let env = TestEnv::setup();

    test_icrc2_approve_ok_without_created_at_time(&env);
    // The test should be able to run many times with no
    // issues as it doesn't mark the transactions for deduplication.
    test_icrc2_approve_ok_without_created_at_time(&env);
    // Test with created_at_time set.
    test_icrc2_approve_ok_with_created_at_time(&env);
    // Move time forward to change the transaction created_at_time
    env.state_machine.advance_time(Duration::from_secs(1));
    // Submit again transactions. created_at_time has changed which
    // means no deduplication should happen
    test_icrc2_approve_ok_with_created_at_time(&env);
}

#[test]
fn test_icrc2_approve_failures() {
    let env = TestEnv::setup();

    test_icrc2_approve_invalid_arg(&env);
    test_icrc2_approve_insufficient_funds(&env);
    test_icrc2_approve_duplicate(&env);
}

fn test_icrc2_transfer_from_ok_with_params(
    env: &TestEnv,
    set_created_at_time: ShouldSetCreatedAtTime,
    set_fee: ShouldSetFee,
    set_memo: ShouldSetMemo,
) {
    // Make a transfer that must succeed and check the Ledger has changed
    // accordingly.

    let account_from = account(1, None);
    let account_to = account(2, None);
    let account_spender = account(3, None);
    let amount = 1_000_000_000;
    let fee = env.icrc1_fee();
    let args_created_at_time = set_created_at_time.then_some(env.nanos_since_epoch_u64());
    let args_fee = set_fee.then_some(fee);
    let args_memo = set_memo.then_some(Memo::from(vec![1u8; 32]));

    // deposit the fee for approve plus the fee + amount for the transfer
    let _deposit_res = env.deposit(account_from, amount + 3 * fee, None);

    // approve so that transfer_from can succeed
    let args = ApproveArgs {
        from_subaccount: account_from.subaccount,
        spender: account_spender,
        amount: Nat::from(amount + fee),
        expected_allowance: None,
        expires_at: None,
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let _approve_index = env.icrc2_approve_or_trap(account_from.owner, args);

    // state that should change after the transfer is executed
    let account_from_balance_before = env.icrc1_balance_of(account_from);
    let account_to_balance_before = env.icrc1_balance_of(account_to);
    let account_spender_balance_before = env.icrc1_balance_of(account_spender);
    let total_supply_before = env.icrc1_total_supply();
    let mut expected_blocks = env.get_all_blocks();

    let args = TransferFromArgs {
        from: account_from,
        to: account_to,
        spender_subaccount: account_spender.subaccount,
        amount: Nat::from(amount),
        fee: args_fee.map(Nat::from),
        created_at_time: args_created_at_time,
        memo: args_memo.clone(),
    };
    let block_index = env.icrc2_transfer_from_or_trap(account_spender.owner, args);

    assert_eq!(
        env.icrc1_balance_of(account_from),
        account_from_balance_before - amount - fee,
    );
    assert_eq!(
        env.icrc1_balance_of(account_to),
        account_to_balance_before + amount,
    );
    assert_eq!(
        env.icrc1_balance_of(account_spender),
        account_spender_balance_before,
    );
    assert_eq!(env.icrc1_total_supply(), total_supply_before - fee,);

    let expected_new_block = Block {
        transaction: Transaction {
            operation: Operation::Transfer {
                from: account_from,
                to: account_to,
                spender: Some(account_spender),
                amount,
                fee: args_fee,
            },
            created_at_time: args_created_at_time,
            memo: args_memo,
        },
        timestamp: env.nanos_since_epoch_u64(),
        phash: Some(env.get_block(block_index - 1u8).hash()),
        effective_fee: args_fee.xor(Some(fee)),
    };
    expected_blocks.push(expected_new_block);
    assert_vec_display_eq(expected_blocks, env.get_all_blocks());
}

fn test_icrc2_transfer_from_ok_without_created_at_time(env: &TestEnv) {
    use ShouldSetCreatedAtTime::*;
    use ShouldSetFee::*;
    use ShouldSetMemo::*;

    // This function is safe to be called multiple times because
    // the transactions it creates are not marked for deduplication.
    test_icrc2_transfer_from_ok_with_params(env, DontSetCreatedAtTime, DontSetFee, DontSetMemo);
    test_icrc2_transfer_from_ok_with_params(env, DontSetCreatedAtTime, SetFee, DontSetMemo);
    test_icrc2_transfer_from_ok_with_params(env, DontSetCreatedAtTime, DontSetFee, SetMemo);
    test_icrc2_transfer_from_ok_with_params(env, DontSetCreatedAtTime, SetFee, SetMemo);
}

fn test_icrc2_transfer_from_ok_with_created_at_time(env: &TestEnv) {
    use ShouldSetCreatedAtTime::*;
    use ShouldSetFee::*;
    use ShouldSetMemo::*;

    // Like [test_icrc1_transfer_ok_without_created_at_time] but
    // created_at_time is set so this function can be called once
    // per deduplication window.
    test_icrc2_transfer_from_ok_with_params(env, SetCreatedAtTime, DontSetFee, DontSetMemo);
    test_icrc2_transfer_from_ok_with_params(env, SetCreatedAtTime, SetFee, DontSetMemo);
    test_icrc2_transfer_from_ok_with_params(env, SetCreatedAtTime, DontSetFee, SetMemo);
    test_icrc2_transfer_from_ok_with_params(env, SetCreatedAtTime, SetFee, SetMemo);
}

fn test_icrc2_transfer_from_invalid_fee(env: &TestEnv) {
    let account_to = account(2, None);
    let account_from = account(3, None);
    let account_spender = account(4, None);
    let fee = env.icrc1_fee();

    // deposit enough funds to account_to such that the transaction
    // should happen if correct
    let _deposit_index = env.deposit(account_from, 3 * fee, None);
    let args = ApproveArgs {
        from_subaccount: account_from.subaccount,
        spender: account_spender,
        amount: Nat::from(fee),
        expected_allowance: None,
        expires_at: None,
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let _approve_index = env.icrc2_approve_or_trap(account_from.owner, args);

    let account_to_balance = env.icrc1_balance_of(account_to);
    let account_from_balance = env.icrc1_balance_of(account_from);
    let account_spender_balance = env.icrc1_balance_of(account_spender);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();

    for bad_fee in [0, fee - 1, fee + 1, u128::MAX] {
        let args = TransferFromArgs {
            from: account_from,
            to: account_to,
            spender_subaccount: account_spender.subaccount,
            amount: Nat::from(0u8),
            fee: Some(Nat::from(bad_fee)),
            created_at_time: None,
            memo: None,
        };
        assert_eq!(
            Err(TransferFromError::BadFee {
                expected_fee: Nat::from(fee)
            }),
            env.icrc2_transfer_from(account_from.owner, args),
        );
    }
    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(account_to_balance, env.icrc1_balance_of(account_to));
    assert_eq!(
        account_spender_balance,
        env.icrc1_balance_of(account_spender)
    );
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc2_transfer_from_too_old(env: &TestEnv) {
    // A transaction is too old if its created_at_time is
    // before ledger_time - TRANSACTION_WINDOW - PERMITTED_DRIFT
    let ledger_time = env.nanos_since_epoch_u64();
    let too_old_created_at_time = Duration::from_nanos(ledger_time)
        - config::TRANSACTION_WINDOW
        - config::PERMITTED_DRIFT
        - Duration::from_nanos(1);

    let account_to = account(2, None);
    let account_from = account(3, None);
    let account_spender = account(4, None);
    let fee = env.icrc1_fee();

    // deposit enough funds to account_to such that the transaction
    // would be accepted if created_at_time was correct
    let _deposit_index = env.deposit(account_from, 3 * fee, None);
    let args = ApproveArgs {
        from_subaccount: account_from.subaccount,
        spender: account_spender,
        amount: Nat::from(fee),
        expected_allowance: None,
        expires_at: None,
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let _approve_index = env.icrc2_approve_or_trap(account_from.owner, args);

    let account_to_balance = env.icrc1_balance_of(account_to);
    let account_from_balance = env.icrc1_balance_of(account_from);
    let account_spender_balance = env.icrc1_balance_of(account_spender);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();

    let args = TransferFromArgs {
        from: account_from,
        to: account_to,
        spender_subaccount: account_spender.subaccount,
        amount: Nat::from(0u8),
        fee: None,
        created_at_time: Some(too_old_created_at_time.as_nanos() as u64),
        memo: None,
    };
    assert_eq!(
        Err(TransferFromError::TooOld),
        env.icrc2_transfer_from(account_spender.owner, args),
    );
    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(account_to_balance, env.icrc1_balance_of(account_to));
    assert_eq!(
        account_spender_balance,
        env.icrc1_balance_of(account_spender)
    );
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc2_transfer_from_in_the_future(env: &TestEnv) {
    // A transaction is in the future if its created_at_time is
    // after ledger_time + PERMITTED_DRIFT
    let ledger_time = env.nanos_since_epoch_u64();
    let in_the_future_created_at_time =
        Duration::from_nanos(ledger_time) + config::PERMITTED_DRIFT + Duration::from_nanos(1);

    let account_to = account(2, None);
    let account_from = account(3, None);
    let account_spender = account(4, None);
    let fee = env.icrc1_fee();

    // deposit enough funds to account_to such that the transaction
    // would be accepted if created_at_time was correct
    let _deposit_index = env.deposit(account_from, 3 * fee, None);
    let args = ApproveArgs {
        from_subaccount: account_from.subaccount,
        spender: account_spender,
        amount: Nat::from(fee),
        expected_allowance: None,
        expires_at: None,
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let _approve_index = env.icrc2_approve_or_trap(account_from.owner, args);

    let account_to_balance = env.icrc1_balance_of(account_to);
    let account_from_balance = env.icrc1_balance_of(account_from);
    let account_spender_balance = env.icrc1_balance_of(account_spender);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();

    let args = TransferFromArgs {
        from: account_from,
        to: account_to,
        spender_subaccount: account_spender.subaccount,
        amount: Nat::from(0u8),
        fee: None,
        created_at_time: Some(in_the_future_created_at_time.as_nanos() as u64),
        memo: None,
    };
    assert_eq!(
        Err(TransferFromError::CreatedInFuture { ledger_time }),
        env.icrc2_transfer_from(account_spender.owner, args),
    );
    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(account_to_balance, env.icrc1_balance_of(account_to));
    assert_eq!(
        account_spender_balance,
        env.icrc1_balance_of(account_spender)
    );
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc2_transfer_from_invalid_arg(env: &TestEnv) {
    test_icrc2_transfer_from_invalid_fee(env);
    test_icrc2_transfer_from_too_old(env);
    test_icrc2_transfer_from_in_the_future(env);
}

fn test_icrc2_transfer_from_insufficient_funds_with_params(
    env: &TestEnv,
    set_created_at_time: ShouldSetCreatedAtTime,
    set_fee: ShouldSetFee,
    set_memo: ShouldSetMemo,
) {
    let account_from = account(100, None);
    let account_to = account(2, None);
    let account_spender = account(4, None);
    let fee = env.icrc1_fee();

    let _deposit_index = env.deposit(account_from, 4 * fee, None);
    // remove the cycles from account_from minus the 2 fees needed
    // for the test
    let amount_to_remove = env.icrc1_balance_of(account_from).saturating_sub(3 * fee);
    let args = TransferArgs {
        from_subaccount: account_from.subaccount,
        to: account_to,
        fee: None,
        created_at_time: None,
        memo: None,
        amount: Nat::from(amount_to_remove),
    };
    let _transfer_index = env.icrc1_transfer_or_trap(account_from.owner, args);
    let args = ApproveArgs {
        from_subaccount: account_from.subaccount,
        spender: account_spender,
        amount: Nat::from(fee + 1),
        expected_allowance: None,
        expires_at: None,
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let _approve_index = env.icrc2_approve_or_trap(account_from.owner, args);

    let account_from_balance = env.icrc1_balance_of(account_from);
    let account_to_balance = env.icrc1_balance_of(account_to);
    let account_spender_balance = env.icrc1_balance_of(account_spender);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();

    let args = TransferFromArgs {
        from: account_from,
        to: account_to,
        spender_subaccount: account_spender.subaccount,
        // Amount is 1 cycle more than what account_from can transfer
        amount: Nat::from(1u8),
        fee: set_fee.then_some(Nat::from(fee)),
        created_at_time: set_created_at_time.then_some(env.nanos_since_epoch_u64()),
        memo: set_memo.then_some(Memo::from(vec![2; 32])),
    };
    assert_eq!(
        Err(TransferFromError::InsufficientFunds {
            balance: Nat::from(account_from_balance)
        }),
        env.icrc2_transfer_from(account_spender.owner, args)
    );
    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(account_to_balance, env.icrc1_balance_of(account_to));
    assert_eq!(
        account_spender_balance,
        env.icrc1_balance_of(account_spender),
    );
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc2_transfer_from_approval_expired(env: &TestEnv) {
    let account_from = account(12351, None);
    let account_to = account(2, None);
    let account_spender = account(4, None);
    let fee = env.icrc1_fee();
    let now = env.nanos_since_epoch_u64();
    let expiry_duration = Duration::from_nanos(1_000_000);
    let expires_at = now + (expiry_duration.as_nanos() as u64);

    let _deposit_index = env.deposit(account_from, 4 * fee, None);
    let amount_to_remove = env.icrc1_balance_of(account_from).saturating_sub(fee);

    env.icrc2_approve_or_trap(
        account_from.owner,
        ApproveArgs {
            from_subaccount: account_from.subaccount,
            spender: account_spender,
            amount: Nat::from(amount_to_remove + fee),
            expected_allowance: None,
            expires_at: Some(expires_at),
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    env.advance_time(expiry_duration);

    let account_from_balance = env.icrc1_balance_of(account_from);
    let account_to_balance = env.icrc1_balance_of(account_to);
    let account_spender_balance = env.icrc1_balance_of(account_spender);
    let total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks();

    let args = TransferFromArgs {
        from: account_from,
        to: account_to,
        spender_subaccount: account_spender.subaccount,
        amount: amount_to_remove.into(),
        fee: None,
        created_at_time: None,
        memo: None,
    };
    // As soon as time >= expires_at the allowance no longer exists
    assert_eq!(expires_at, env.nanos_since_epoch_u64());
    assert_eq!(
        Err(expired_approval()),
        env.icrc2_transfer_from(account_spender.owner, args)
    );
    assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
    assert_eq!(account_to_balance, env.icrc1_balance_of(account_to));
    assert_eq!(
        account_spender_balance,
        env.icrc1_balance_of(account_spender),
    );
    assert_eq!(total_supply, env.icrc1_total_supply());
    assert_vec_display_eq(blocks, env.get_all_blocks());
}

fn test_icrc2_transfer_from_insufficient_funds(env: &TestEnv) {
    use ShouldSetCreatedAtTime::*;
    use ShouldSetFee::*;
    use ShouldSetMemo::*;

    // test_icrc1_transfer_insufficient_funds_with_params takes in input 3 booleans
    // set_created_at_time, set_fee and set_memo.
    // Try all the permutations.
    test_icrc2_transfer_from_insufficient_funds_with_params(
        env,
        DontSetCreatedAtTime,
        DontSetFee,
        DontSetMemo,
    );
    test_icrc2_transfer_from_insufficient_funds_with_params(
        env,
        DontSetCreatedAtTime,
        SetFee,
        DontSetMemo,
    );
    test_icrc2_transfer_from_insufficient_funds_with_params(
        env,
        DontSetCreatedAtTime,
        DontSetFee,
        SetMemo,
    );
    test_icrc2_transfer_from_insufficient_funds_with_params(
        env,
        DontSetCreatedAtTime,
        SetFee,
        SetMemo,
    );
    test_icrc2_transfer_from_insufficient_funds_with_params(
        env,
        SetCreatedAtTime,
        DontSetFee,
        DontSetMemo,
    );
    test_icrc2_transfer_from_insufficient_funds_with_params(
        env,
        SetCreatedAtTime,
        SetFee,
        DontSetMemo,
    );
    test_icrc2_transfer_from_insufficient_funds_with_params(
        env,
        SetCreatedAtTime,
        SetFee,
        DontSetMemo,
    );
    test_icrc2_transfer_from_insufficient_funds_with_params(env, SetCreatedAtTime, SetFee, SetMemo);
}

fn test_icrc2_transfer_from_duplicate_with_params(
    env: &TestEnv,
    set_fee: ShouldSetFee,
    set_memo: ShouldSetMemo,
    has_fee_for_second_transfer: bool,
) {
    let account_from = account(1, None);
    let account_to = account(2, None);
    let account_spender = account(3, None);
    let fee = env.icrc1_fee();
    let ledger_time = Duration::from_nanos(env.nanos_since_epoch_u64());

    // Try different valid non-optional created_at_time
    for created_at_time in [
        // 1 nanosecond before being too old
        ledger_time - config::TRANSACTION_WINDOW - config::PERMITTED_DRIFT,
        // 1 nanosecond before ledger_time
        ledger_time - Duration::from_nanos(1),
        // 1 nanosecond after ledger_time
        ledger_time + Duration::from_nanos(1),
        // 1 nanosecond before being in the future
        ledger_time + config::PERMITTED_DRIFT,
    ] {
        let amount_to_deposit = if has_fee_for_second_transfer {
            4 * fee
        } else {
            3 * fee
        };
        let _deposit_index = env.deposit(account_from, amount_to_deposit + fee, None);

        // remove the cycles from account_from minus the fees needed
        // for the test
        let amount_to_remove = env
            .icrc1_balance_of(account_from)
            .saturating_sub(amount_to_deposit);
        let args = TransferArgs {
            from_subaccount: account_from.subaccount,
            to: account_to,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(amount_to_remove),
        };
        let _transfer_index = env.icrc1_transfer_or_trap(account_from.owner, args);
        let args = ApproveArgs {
            from_subaccount: account_from.subaccount,
            spender: account_spender,
            amount: Nat::from(fee),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        };
        let _approve_index = env.icrc2_approve_or_trap(account_from.owner, args);

        let args = TransferFromArgs {
            from: account_from,
            to: account_to,
            spender_subaccount: account_spender.subaccount,
            // Amount is 1 cycle more than what account_from can transfer
            amount: Nat::from(0u8),
            fee: set_fee.then_some(Nat::from(fee)),
            created_at_time: Some(created_at_time.as_nanos() as u64),
            memo: set_memo.then_some(Memo::from(vec![3; 32])),
        };
        let block_index = env.icrc2_transfer_from_or_trap(account_spender.owner, args.clone());

        let account_from_balance = env.icrc1_balance_of(account_from);
        let account_to_balance = env.icrc1_balance_of(account_to);
        let account_spender_balance = env.icrc1_balance_of(account_spender);
        let total_supply = env.icrc1_total_supply();
        let blocks = env.get_all_blocks();

        assert_eq!(
            Err(TransferFromError::Duplicate {
                duplicate_of: block_index
            }),
            env.icrc2_transfer_from(account_spender.owner, args),
        );

        assert_eq!(account_from_balance, env.icrc1_balance_of(account_from));
        assert_eq!(account_to_balance, env.icrc1_balance_of(account_to));
        assert_eq!(
            account_spender_balance,
            env.icrc1_balance_of(account_spender)
        );
        assert_eq!(total_supply, env.icrc1_total_supply());
        assert_vec_display_eq(&blocks, env.get_all_blocks());
    }
}

fn test_icrc2_transfer_from_duplicate(env: &TestEnv) {
    use ShouldSetFee::*;
    use ShouldSetMemo::*;

    test_icrc2_transfer_from_duplicate_with_params(env, DontSetFee, DontSetMemo, false);
    test_icrc2_transfer_from_duplicate_with_params(env, SetFee, DontSetMemo, false);
    test_icrc2_transfer_from_duplicate_with_params(env, DontSetFee, SetMemo, false);
    test_icrc2_transfer_from_duplicate_with_params(env, SetFee, SetMemo, false);
    // Change the ledger time to avoid duplicates between the first
    // four tests and the next four tests.
    env.state_machine.advance_time(Duration::from_nanos(1));
    test_icrc2_transfer_from_duplicate_with_params(env, DontSetFee, DontSetMemo, true);
    test_icrc2_transfer_from_duplicate_with_params(env, SetFee, DontSetMemo, true);
    test_icrc2_transfer_from_duplicate_with_params(env, DontSetFee, SetMemo, true);
    test_icrc2_transfer_from_duplicate_with_params(env, SetFee, SetMemo, true);
}

#[test]
fn test_icrc2_transfer_from() {
    let env = TestEnv::setup();

    test_icrc2_transfer_from_ok_without_created_at_time(&env);
    // The test should be able to run many times with no
    // issues as it doesn't mark the transasctions for deduplication.
    test_icrc2_transfer_from_ok_without_created_at_time(&env);
    // Test icrc1_transfer with created_at_time set.
    test_icrc2_transfer_from_ok_with_created_at_time(&env);
    // Move time forward to change the transaction created_at_time
    env.state_machine.advance_time(Duration::from_secs(1));
    // Submit again transactions. created_at_time has changed which
    // means no deduplication should happen
    test_icrc2_transfer_from_ok_with_created_at_time(&env);
}

#[test]
fn test_icrc2_transfer_from_failures() {
    let env = TestEnv::setup();

    test_icrc2_transfer_from_invalid_arg(&env);
    test_icrc2_transfer_from_insufficient_funds(&env);
    test_icrc2_transfer_from_approval_expired(&env);
    test_icrc2_transfer_from_duplicate(&env);
}

#[test]
fn test_icrc2_transfer_fails_if_approve_smaller_than_amount_plus_fee() {
    let env = TestEnv::setup();
    let account1 = account(1, None);
    let account2 = account(2, None);
    let fee = env.icrc1_fee();

    let deposit_res = env.deposit(account1, 3 * fee, None);
    let approve_block_index = env.icrc2_approve_or_trap(
        account1.owner,
        ApproveArgs {
            from_subaccount: account1.subaccount,
            spender: account2,
            amount: Nat::from(fee - 1),
            expected_allowance: Some(Nat::from(0u64)),
            expires_at: Some(u64::MAX),
            fee: Some(Nat::from(fee)),
            memo: None,
            created_at_time: None,
        },
    );
    let block = env.get_block(approve_block_index);
    assert_display_eq(
        Block {
            phash: Some(env.get_block_hash(deposit_res.block_index)),
            effective_fee: None,
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                operation: Operation::Approve {
                    from: account1,
                    spender: account2,
                    amount: fee - 1,
                    expected_allowance: Some(0),
                    expires_at: Some(u64::MAX),
                    fee: Some(fee),
                },
                memo: None,
                created_at_time: None,
            },
        },
        block,
    );
    let expected_blocks = env.get_all_blocks();
    let transfer_from_block_err = env.icrc2_transfer_from(
        account2.owner,
        TransferFromArgs {
            spender_subaccount: account2.subaccount,
            from: account1,
            to: account2,
            amount: Nat::from(0u64),
            fee: Some(Nat::from(fee)),
            memo: None,
            created_at_time: None,
        },
    );

    assert_eq!(
        transfer_from_block_err,
        Err(TransferFromError::InsufficientAllowance {
            allowance: Nat::from(fee - 1)
        }),
    );
    assert_eq!(expected_blocks, env.get_all_blocks());
}

#[test]
fn test_deduplication() {
    let env = TestEnv::setup();
    let account1 = account(1, None);
    let account2 = account(2, None);
    let fee = env.icrc1_fee();

    let deposit_res = env.deposit(account1, 3 * fee, None);
    let approve_block_index = env.icrc2_approve_or_trap(
        account1.owner,
        ApproveArgs {
            from_subaccount: account1.subaccount,
            spender: account2,
            amount: Nat::from(fee - 1),
            expected_allowance: Some(Nat::from(0u64)),
            expires_at: Some(u64::MAX),
            fee: Some(Nat::from(fee)),
            memo: None,
            created_at_time: None,
        },
    );
    let block = env.get_block(approve_block_index);
    assert_display_eq(
        Block {
            phash: Some(env.get_block_hash(deposit_res.block_index)),
            effective_fee: None,
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                operation: Operation::Approve {
                    from: account1,
                    spender: account2,
                    amount: fee - 1,
                    expected_allowance: Some(0),
                    expires_at: Some(u64::MAX),
                    fee: Some(fee),
                },
                memo: None,
                created_at_time: None,
            },
        },
        block,
    );
    let expected_blocks = env.get_all_blocks();
    let transfer_from_block_err = env.icrc2_transfer_from(
        account2.owner,
        TransferFromArgs {
            spender_subaccount: account2.subaccount,
            from: account1,
            to: account2,
            amount: Nat::from(0u64),
            fee: Some(Nat::from(fee)),
            memo: None,
            created_at_time: None,
        },
    );

    assert_eq!(
        transfer_from_block_err,
        Err(TransferFromError::InsufficientAllowance {
            allowance: Nat::from(fee - 1)
        }),
    );
    assert_eq!(expected_blocks, env.get_all_blocks());
}

#[ignore = "FI-1284 The docker build doesn't support features because we want to test the production wasm. This test should be rewritten to use only the public endpoints"]
#[test]
fn test_pruning_transactions() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let account1 = account(1, None);
    let account2 = account(2, None);
    let transfer_amount = Nat::from(100_000_u128);

    let check_tx_hashes = |length: u64, first_block: u64, last_block: u64| {
        let tx_hashes = env.transaction_hashes();
        let mut idxs: Vec<&u64> = tx_hashes.values().collect::<Vec<&u64>>();
        idxs.sort();
        assert_eq!(idxs.len() as u64, length);
        assert_eq!(*idxs[0], first_block);
        assert_eq!(*idxs[idxs.len() - 1], last_block);
    };
    let check_tx_timestamps =
        |length: u64, first_timestamp: (u64, u64), last_timestamp: (u64, u64)| {
            let tx_timestamps = env.transaction_timestamps();
            assert_eq!(
                tx_timestamps.first_key_value().unwrap(),
                (&first_timestamp, &())
            );
            assert_eq!(
                tx_timestamps.last_key_value().unwrap(),
                (&last_timestamp, &())
            );
            assert_eq!(tx_timestamps.len() as u64, length);
        };

    let tx_hashes = env.transaction_hashes();
    // There have not been any transactions. The transaction hashes log should be empty
    assert!(tx_hashes.is_empty());

    let deposit_amount = 100_000_000_000;
    env.deposit(account1, deposit_amount + fee, None);

    // A deposit does not have a `created_at_time` argument and is therefore not recorded
    let tx_hashes = env.transaction_hashes();
    assert!(tx_hashes.is_empty());

    // Create a transfer where `created_at_time` is not set
    let _block_index = env
        .icrc1_transfer(
            account1.owner,
            TransferArgs {
                from_subaccount: None,
                to: account2,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
        .unwrap();

    // There should not be an entry for deduplication
    let tx_hashes = env.transaction_hashes();
    assert!(tx_hashes.is_empty());

    let time = env.nanos_since_epoch_u64();
    // Create a transfer with `created_at_time` set
    let block_index = env
        .icrc1_transfer(
            account1.owner,
            TransferArgs {
                from_subaccount: None,
                to: account2,
                fee: None,
                created_at_time: Some(time),
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
        .unwrap()
        .0
        .to_u64()
        .unwrap();

    // There should be one transaction appearing in the transaction queue for deduplication
    check_tx_hashes(1, block_index, block_index);
    check_tx_timestamps(1, (time, block_index), (time, block_index));

    // Create another transaction with the same timestamp but a different hash
    let transfer_idx_3 = env
        .icrc1_transfer(
            account1.owner,
            TransferArgs {
                from_subaccount: None,
                to: account2,
                fee: None,
                created_at_time: Some(time),
                memo: Some(Memo(ByteBuf::from(b"1234".to_vec()))),
                amount: transfer_amount.clone(),
            },
        )
        .unwrap()
        .0
        .to_u64()
        .unwrap();
    // There are now two different tx hashes in 2 different transactions
    check_tx_hashes(2, block_index, transfer_idx_3);
    check_tx_timestamps(2, (time, block_index), (time, transfer_idx_3));

    // Advance time to move the Transaction window
    env.state_machine.advance_time(Duration::from_nanos(
        config::TRANSACTION_WINDOW.as_nanos() as u64
            + config::PERMITTED_DRIFT.as_nanos() as u64 * 2,
    ));
    env.state_machine.tick();
    let time = env.nanos_since_epoch_u64();
    // Create another transaction to trigger pruning
    let block_index = env
        .icrc1_transfer(
            account1.owner,
            TransferArgs {
                from_subaccount: None,
                to: account2,
                fee: None,
                created_at_time: Some(time),
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
        .unwrap()
        .0
        .to_u64()
        .unwrap();
    // Transfers 2 and 3 should be removed leaving only one transfer left
    check_tx_hashes(1, block_index, block_index);
    check_tx_timestamps(1, (time, block_index), (time, block_index));
}

#[test]
fn test_total_supply_after_upgrade() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let account1 = account(1, None);
    let account2 = account(2, None);

    env.deposit(account1, 2_000_000_000 + fee, None);
    env.deposit(account2, 3_000_000_000 + fee, None);
    let fee = env.icrc1_fee();
    let _block_index = env
        .icrc1_transfer(
            account1.owner,
            TransferArgs {
                from_subaccount: None,
                to: account2,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(1_000_000_000_u128),
            },
        )
        .unwrap();
    let _withdraw_res = env
        .withdraw(
            account2.owner,
            WithdrawArgs {
                from_subaccount: account2.subaccount,
                to: env.depositor_id,
                created_at_time: None,
                amount: Nat::from(1_000_000_000_u128),
            },
        )
        .unwrap();

    // total_supply should be 5m - 1m sent back to the depositor - twice the fee for transfer and withdraw
    let expected_total_supply = 5_000_000_000 - 1_000_000_000 - 2 * fee;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    env.upgrade_ledger(None).unwrap();
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
}

#[test]
fn test_icrc3_get_blocks() {
    // Utility to extract all IDs and the corresponding blcks from the given [GetBlocksResult].
    fn decode_blocks_with_ids(blocks: Vec<BlockWithId>) -> Vec<(u64, Block)> {
        blocks
            .into_iter()
            .map(|BlockWithId { id, block }| {
                let block_index = id.0.to_u64().unwrap();
                let block_decoded = Block::from_value(block.clone()).unwrap_or_else(|e| {
                    panic!(
                        "Unable to decode block at index:{block_index} value:{:?} : {e}",
                        block
                    )
                });
                (block_index, block_decoded)
            })
            .collect()
    }

    let env = TestEnv::setup();
    let fee = env.icrc1_fee();

    let get_blocks_res = env.icrc3_get_blocks(vec![(0u64, 10u64)]);
    assert_eq!(get_blocks_res.log_length, 0_u128);
    assert_eq!(get_blocks_res.archived_blocks.len(), 0);
    assert_eq!(decode_blocks_with_ids(get_blocks_res.blocks), vec![]);

    let account1 = account(1, None);
    let account2 = account(2, None);
    let account3 = account(3, None);

    // add the first mint block
    env.deposit(account1, 5_000_000_000 + fee, None);

    let get_blocks_res = env.icrc3_get_blocks(vec![(0u64, 10u64)]);
    assert_eq!(get_blocks_res.log_length, 1_u128);
    assert_eq!(get_blocks_res.archived_blocks.len(), 0);
    let mut block0 = block(
        Mint {
            to: account1,
            amount: 5_000_000_000,
            fee,
        },
        None,
        None,
        None,
    );
    let actual_blocks = decode_blocks_with_ids(get_blocks_res.blocks);
    let expected_blocks = vec![(0, block0.clone())];
    assert_blocks_eq_except_ts(&actual_blocks, &expected_blocks);
    // Replace the dummy timestamp in the crafted block with the real one,
    // i.e., the timestamp the ledger wrote in the real block. This is required
    // so that we can use the hash of the block as the parent hash.
    block0.timestamp = actual_blocks[0].1.timestamp;
    env.validate_certificate(0, block0.clone().hash());

    // add a second mint block
    env.deposit(account2, 3_000_000_000 + fee, None);

    let get_blocks_res = env.icrc3_get_blocks(vec![(0u64, 10u64)]);
    assert_eq!(get_blocks_res.log_length, 2_u128);
    assert_eq!(get_blocks_res.archived_blocks.len(), 0);
    let mut block1 = block(
        Mint {
            to: account2,
            amount: 3_000_000_000,
            fee,
        },
        None,
        None,
        Some(block0.clone().hash()),
    );
    let actual_blocks = decode_blocks_with_ids(get_blocks_res.blocks);
    let expected_blocks = vec![(0, block0.clone()), (1, block1.clone())];
    assert_blocks_eq_except_ts(&actual_blocks, &expected_blocks);
    // Replace the dummy timestamp in the crafted block with the real one,
    // i.e., the timestamp the ledger wrote in the real block. This is required
    // so that we can use the hash of the block as the parent hash.
    block1.timestamp = actual_blocks[1].1.timestamp;
    env.validate_certificate(1, block1.clone().hash());

    // check retrieving a subset of the transactions
    let get_blocks_res = env.icrc3_get_blocks(vec![(0u64, 1u64)]);
    assert_eq!(get_blocks_res.log_length, 2_u128);
    assert_eq!(get_blocks_res.archived_blocks.len(), 0);
    let actual_blocks = decode_blocks_with_ids(get_blocks_res.blocks);
    let expected_blocks = vec![(0, block0.clone())];
    assert_blocks_eq_except_ts(&actual_blocks, &expected_blocks);

    // add a burn block
    let _withdraw_res = env
        .withdraw(
            account2.owner,
            WithdrawArgs {
                from_subaccount: account2.subaccount,
                to: env.depositor_id,
                created_at_time: None,
                amount: Nat::from(2_000_000_000_u128),
            },
        )
        .expect("Withdraw failed");

    let get_blocks_res = env.icrc3_get_blocks(vec![(0u64, 10u64)]);
    assert_eq!(get_blocks_res.log_length, 3_u128);
    assert_eq!(get_blocks_res.archived_blocks.len(), 0);
    let withdraw_memo = encode_withdraw_memo(&env.depositor_id);
    let mut block2 = block(
        Burn {
            from: account2,
            spender: None,
            amount: 2_000_000_000,
        },
        None,
        Some(withdraw_memo),
        Some(block1.clone().hash()),
    );
    let actual_blocks = decode_blocks_with_ids(get_blocks_res.blocks);
    let expected_blocks = vec![
        (0, block0.clone()),
        (1, block1.clone()),
        (2, block2.clone()),
    ];
    assert_blocks_eq_except_ts(&actual_blocks, &expected_blocks);
    // Replace the dummy timestamp in the crafted block with the real one,
    // i.e., the timestamp the ledger wrote in the real block. This is required
    // so that we can use the hash of the block as the parent hash.
    block2.timestamp = actual_blocks[2].1.timestamp;
    env.validate_certificate(2, block2.clone().hash());

    // add a couple of blocks
    let _block_index = env
        .icrc1_transfer(
            account1.owner,
            TransferArgs {
                from_subaccount: None,
                to: account2,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(1_000_000_000_u128),
            },
        )
        .expect("Transfer failed");
    let _block_index = env
        .icrc2_approve(
            account1.owner,
            ApproveArgs {
                from_subaccount: account1.subaccount,
                spender: account2,
                amount: Nat::from(1_000_000_000 + FEE),
                expected_allowance: Some(Nat::from(0u64)),
                expires_at: None,
                fee: Some(Nat::from(FEE)),
                memo: None,
                created_at_time: None,
            },
        )
        .expect("Approve failed");
    let _block_index = env.icrc2_transfer_from_or_trap(
        account2.owner,
        TransferFromArgs {
            spender_subaccount: account2.subaccount,
            from: account1,
            to: account3,
            amount: Nat::from(1_000_000_000u64),
            fee: Some(Nat::from(FEE)),
            memo: None,
            created_at_time: None,
        },
    );

    let get_blocks_res = env.icrc3_get_blocks(vec![(0u64, 10u64)]);
    assert_eq!(get_blocks_res.log_length, 6_u128);
    assert_eq!(get_blocks_res.archived_blocks.len(), 0);
    let actual_blocks = decode_blocks_with_ids(get_blocks_res.blocks);
    let block3 = block(
        Transfer {
            from: account1,
            to: account2,
            spender: None,
            amount: 1_000_000_000,
            fee: None,
        },
        None,
        None,
        Some(block2.clone().hash()),
    );
    let block4 = block(
        Approve {
            from: account1,
            spender: account2,
            amount: 1_000_000_000 + FEE,
            expected_allowance: Some(0),
            expires_at: None,
            fee: Some(FEE),
        },
        None,
        None,
        Some(actual_blocks[3].1.clone().hash()),
    );
    let mut block5 = block(
        Transfer {
            from: account1,
            to: account3,
            spender: Some(account2),
            amount: 1_000_000_000,
            fee: Some(FEE),
        },
        None,
        None,
        Some(actual_blocks[4].1.clone().hash()),
    );
    let expected_blocks = vec![
        (0, block0.clone()),
        (1, block1.clone()),
        (2, block2.clone()),
        (3, block3.clone()),
        (4, block4.clone()),
        (5, block5.clone()),
    ];
    assert_blocks_eq_except_ts(&actual_blocks, &expected_blocks);
    // Replace the dummy timestamp in the crafted block with the real one,
    // i.e., the timestamp the ledger wrote in the real block. This is required
    // so that we can use the hash of the block as the parent hash.
    block5.timestamp = actual_blocks[5].1.timestamp;
    env.validate_certificate(5, block5.hash());
}

// Checks two lists of blocks are the same.
// Skips the timestamp check because timestamps are set by the ledger.
#[track_caller]
fn assert_blocks_eq_except_ts(left: &[(u64, Block)], right: &[(u64, Block)]) {
    assert_eq!(
        left.len(),
        right.len(),
        "The block lists have different sizes!"
    );
    for i in 0..left.len() {
        assert_eq!(
            left[i].0, right[i].0,
            "Blocks at position {} have different indices",
            i
        );
        assert_eq!(
            left[i].1.transaction, right[i].1.transaction,
            "Blocks at position {} have different transactions",
            i
        );
        assert_eq!(
            left[i].1.phash, right[i].1.phash,
            "Blocks at position {} have different parent hashes",
            i
        );
        assert_eq!(
            left[i].1.effective_fee, right[i].1.effective_fee,
            "Blocks at position {} have different effective fees",
            i
        );
    }
}

// Creates a block out of the given operation and metadata with `timestamp` set to [u64::MAX ] and `effective_fee`
// based on the operation.
fn block(
    operation: Operation,
    created_at_time: Option<u64>,
    memo: Option<Memo>,
    phash: Option<[u8; 32]>,
) -> Block {
    let effective_fee = match operation {
        Mint { .. } => Some(0),
        Burn { .. } => Some(FEE),
        Transfer { fee, .. } | Approve { fee, .. } => {
            if fee.is_none() {
                Some(FEE)
            } else {
                None
            }
        }
    };
    Block {
        transaction: Transaction {
            operation,
            created_at_time,
            memo,
        },
        timestamp: u64::MIN,
        phash,
        effective_fee,
    }
}

#[test]
fn test_get_blocks_max_length() {
    // Check that the ledger doesn't return more blocks
    // than configured. We set the max number of blocks
    // per request to 2 instead of the default because
    // it's much faster to test.

    const MAX_BLOCKS_PER_REQUEST: u64 = 2;
    let env = TestEnv::setup_with_ledger_conf(LedgerConfig {
        max_blocks_per_request: MAX_BLOCKS_PER_REQUEST,
        index_id: None,
        initial_balances: None,
    });
    let fee = env.icrc1_fee();

    let account10 = account(10, None);
    let _deposit_res = env.deposit(account10, 1_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account10, 2_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account10, 3_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account10, 4_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account10, 5_000_000_000 + fee, None);

    let res = env.icrc3_get_blocks(vec![(0, u64::MAX)]);
    assert_eq!(MAX_BLOCKS_PER_REQUEST, res.blocks.len() as u64);

    let res = env.icrc3_get_blocks(vec![(3, u64::MAX)]);
    assert_eq!(MAX_BLOCKS_PER_REQUEST, res.blocks.len() as u64);

    let res = env.icrc3_get_blocks(vec![(0, u64::MAX), (2, u64::MAX)]);
    assert_eq!(MAX_BLOCKS_PER_REQUEST, res.blocks.len() as u64);
}

#[test]
fn test_set_max_blocks_per_request_in_upgrade() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();

    let account10 = account(10, None);
    let _deposit_res = env.deposit(account10, 1_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account10, 2_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account10, 3_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account10, 4_000_000_000 + fee, None);
    let _deposit_res = env.deposit(account10, 5_000_000_000 + fee, None);

    let res = env.icrc3_get_blocks(vec![(0, u64::MAX)]);
    assert_eq!(5, res.blocks.len() as u64);

    const MAX_BLOCKS_PER_REQUEST: u64 = 2;
    let arg = Encode!(&Some(LedgerArgs::Upgrade(Some(UpgradeArgs {
        max_blocks_per_request: Some(MAX_BLOCKS_PER_REQUEST),
        change_index_id: None,
    }))))
    .unwrap();
    env.state_machine
        .upgrade_canister(env.ledger_id, get_wasm("cycles-ledger"), arg, None)
        .unwrap();

    let res = env.icrc3_get_blocks(vec![(0, u64::MAX)]);
    assert_eq!(MAX_BLOCKS_PER_REQUEST, res.blocks.len() as u64);

    let res = env.icrc3_get_blocks(vec![(3, u64::MAX)]);
    assert_eq!(MAX_BLOCKS_PER_REQUEST, res.blocks.len() as u64);

    let res = env.icrc3_get_blocks(vec![(0, u64::MAX), (2, u64::MAX)]);
    assert_eq!(MAX_BLOCKS_PER_REQUEST, res.blocks.len() as u64);
}

#[test]
fn test_set_index_id_in_init() {
    let index_id = Principal::from_slice(&[111]);
    let env = TestEnv::setup_with_ledger_conf(LedgerConfig {
        index_id: Some(index_id),
        ..Default::default()
    });
    assert_index_set(&env, &index_id);
}

#[test]
fn test_change_index_id() {
    let env = TestEnv::setup();

    // by default there is no index_id set
    assert_index_not_set(&env);

    // set the index_id
    let index_id = Principal::from_slice(&[111]);
    let args = UpgradeArgs {
        max_blocks_per_request: None,
        change_index_id: Some(ChangeIndexId::SetTo(index_id)),
    };
    env.upgrade_ledger(Some(args)).unwrap();
    assert_index_set(&env, &index_id);

    // unset the index_id
    let args = UpgradeArgs {
        max_blocks_per_request: None,
        change_index_id: Some(ChangeIndexId::Unset),
    };
    env.upgrade_ledger(Some(args)).unwrap();
    assert_index_not_set(&env);
}

fn assert_index_set(env: &TestEnv, index_id: &Principal) {
    let metadata = env.icrc1_metadata();
    assert_eq!(
        metadata
            .iter()
            .find_map(|(k, v)| if k == "dfn:index_id" { Some(v) } else { None }),
        Some(&MetadataValue::from(index_id.as_slice())),
    );
    assert_eq!(
        metadata
            .iter()
            .find_map(|(k, v)| if k == "icrc106:index_principal" {
                Some(v)
            } else {
                None
            }),
        Some(&MetadataValue::from(index_id.to_text())),
    );
    assert_eq!(env.icrc106_index_principal(), Ok(*index_id));
}

fn assert_index_not_set(env: &TestEnv) {
    let metadata = env.icrc1_metadata();
    assert!(metadata.iter().all(|(k, _)| k != "dfn:index_id"));
    assert!(metadata.iter().all(|(k, _)| k != "icrc106:index_principal"));
    assert_eq!(
        env.icrc106_index_principal(),
        Err(Icrc106Error::IndexPrincipalNotSet)
    );
}

#[tokio::test]
async fn test_icrc1_test_suite() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let account10 = account(10, None);

    // make the first deposit to the user and check the result
    let deposit_res = env.deposit(account10, 1_000_000_000_000_000 + fee, None);
    assert_eq!(deposit_res.block_index, Nat::from(0_u128));
    assert_eq!(deposit_res.balance, 1_000_000_000_000_000_u128);
    assert_eq!(1_000_000_000_000_000, env.icrc1_balance_of(account10));

    #[allow(clippy::arc_with_non_send_sync)]
    let ledger_env = icrc1_test_env_state_machine::SMLedger::new(
        Arc::new(env.state_machine),
        env.ledger_id,
        account10.owner,
    );
    let tests = icrc1_test_suite::test_suite(ledger_env).await;
    if !icrc1_test_suite::execute_tests(tests).await {
        panic!("The ICRC-1 test suite failed");
    }
}

#[test]
fn test_upgrade_preserves_state() {
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::TestRunner;

    let mut env = TestEnv::setup();
    let depositor_cycles = env.state_machine.cycle_balance(env.depositor_id);
    let mut expected_state = CyclesLedgerInMemory::new(depositor_cycles);

    // generate a list of calls for the cycles ledger
    let now = env.nanos_since_epoch_u64();
    let calls = gen::arb_cycles_ledger_call_state(env.depositor_id, depositor_cycles, 10, now)
        .new_tree(&mut TestRunner::default())
        .unwrap()
        .current()
        .calls;

    println!("=== Test started ===");

    println!("Running the following operations on the Ledger:");
    for (i, call) in calls.into_iter().enumerate() {
        println!(" #{} {}", i, call);

        expected_state
            .execute(&call)
            .expect("Unable to perform call on in-memory state");
        env.execute(&call)
            .expect("Unable to perform call on StateMachine");

        // check that the state is consistent with `expected_state`
        check_ledger_state(&env, &expected_state);
    }

    let expected_blocks = env.icrc3_get_blocks(vec![(0u64, u64::MAX)]);

    env.upgrade_ledger(None).unwrap();

    // check that the state is still consistent with `expected_state`
    // after the upgrade
    check_ledger_state(&env, &expected_state);

    // check that the blocks are all there after the upgrade
    let after_upgrade_blocks = env.icrc3_get_blocks(vec![(0u64, u64::MAX)]);
    assert_eq!(expected_blocks, after_upgrade_blocks);
}

#[track_caller]
fn check_ledger_state(env: &TestEnv, expected_state: &CyclesLedgerInMemory) {
    assert_eq!(expected_state.total_supply, env.icrc1_total_supply());

    for (account, balance) in &expected_state.balances {
        assert_eq!(
            balance,
            &env.icrc1_balance_of(*account),
            "balance_of({})",
            account
        );
    }

    for ((from, spender), allowance) in &expected_state.allowances {
        let actual_allowance = env.icrc2_allowance(*from, *spender).allowance;
        assert_eq!(
            allowance,
            &actual_allowance.0.to_u128().unwrap(),
            "allowance({}, {})",
            from,
            spender
        );
    }
}

#[test]
fn test_create_canister() {
    const CREATE_CANISTER_CYCLES: u128 = 1_000_000_000_000;
    const CREATE_CANISTER_CYCLES_MINUS_FEE: u128 = 1_000_000_000_000 - FEE;
    let env = new_state_machine();
    install_fake_cmc(&env);
    let ledger_id = install_ledger(&env);
    let depositor_id = install_depositor(&env, ledger_id);
    let account10_0 = Account {
        owner: Principal::from_slice(&[10]),
        subaccount: Some([0; 32]),
    };
    let mut expected_balance = 1_000_000_000_000_000_u128;

    // make the first deposit to the user and check the result
    let deposit_res = deposit(
        &env,
        depositor_id,
        account10_0,
        expected_balance + config::FEE,
        None,
    );
    assert_eq!(deposit_res.block_index, Nat::from(0_u128));
    assert_eq!(deposit_res.balance, expected_balance);
    assert_eq!(
        expected_balance,
        icrc1_balance_of(&env, ledger_id, account10_0)
    );

    // successful create
    let canister = create_canister(
        &env,
        ledger_id,
        account10_0.owner,
        CreateCanisterArgs {
            from_subaccount: account10_0.subaccount,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
        },
    )
    .unwrap()
    .canister_id;
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    let status = canister_status(&env, canister, account10_0.owner);
    assert_eq!(
        expected_balance,
        icrc1_balance_of(&env, ledger_id, account10_0)
    );
    // no canister creation fee on system subnet (where the StateMachine is by default)
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    assert_eq!(vec![account10_0.owner], status.settings.controllers);

    let canister_settings = CanisterSettings {
        controllers: Some(vec![account10_0.owner, Principal::anonymous()]),
        compute_allocation: Some(Nat::from(7_u128)),
        memory_allocation: Some(Nat::from(8_u128)),
        freezing_threshold: Some(Nat::from(9_u128)),
        reserved_cycles_limit: Some(Nat::from(10_u128)),
    };
    let CreateCanisterSuccess {
        canister_id,
        block_id,
    } = create_canister(
        &env,
        ledger_id,
        account10_0.owner,
        CreateCanisterArgs {
            from_subaccount: account10_0.subaccount,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: Some(CmcCreateCanisterArgs {
                subnet_selection: None,
                settings: Some(canister_settings.clone()),
            }),
        },
    )
    .unwrap();
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    let status = canister_status(&env, canister_id, account10_0.owner);
    assert_eq!(
        expected_balance,
        icrc1_balance_of(&env, ledger_id, account10_0)
    );
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    // order is not guaranteed
    assert_eq!(
        HashSet::<Principal>::from_iter(status.settings.controllers.iter().cloned()),
        HashSet::from_iter(canister_settings.controllers.unwrap().iter().cloned())
    );
    assert_eq!(
        status.settings.freezing_threshold,
        canister_settings.freezing_threshold.unwrap()
    );
    assert_eq!(
        status.settings.compute_allocation,
        canister_settings.compute_allocation.unwrap()
    );
    assert_eq!(
        status.settings.memory_allocation,
        canister_settings.memory_allocation.unwrap()
    );
    assert_eq!(
        status.settings.reserved_cycles_limit,
        canister_settings.reserved_cycles_limit.unwrap()
    );
    assert_matches!(
        get_block(&env, ledger_id, block_id).transaction.operation,
        Operation::Burn {
            amount: CREATE_CANISTER_CYCLES,
            ..
        }
    );

    // If `CanisterSettings` do not specify a controller, the caller should still control the resulting canister
    // `creation_args` is `Some`, `canister_settings` is `Some`, `controllers` is `None`
    let canister_settings = CanisterSettings {
        controllers: None,
        compute_allocation: Some(Nat::from(7_u128)),
        memory_allocation: Some(Nat::from(8_u128)),
        freezing_threshold: Some(Nat::from(9_u128)),
        reserved_cycles_limit: Some(Nat::from(10_u128)),
    };
    let CreateCanisterSuccess { canister_id, .. } = create_canister(
        &env,
        ledger_id,
        account10_0.owner,
        CreateCanisterArgs {
            from_subaccount: account10_0.subaccount,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: Some(CmcCreateCanisterArgs {
                subnet_selection: None,
                settings: Some(canister_settings),
            }),
        },
    )
    .unwrap();
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    let status = canister_status(&env, canister_id, account10_0.owner);
    assert_eq!(
        expected_balance,
        icrc1_balance_of(&env, ledger_id, account10_0)
    );
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    assert_eq!(status.settings.controllers, vec![account10_0.owner]);

    // If `CanisterSettings` do not specify a controller, the caller should still control the resulting canister
    // `creation_args` is `Some`, `canister_settings` is `None`
    let CreateCanisterSuccess { canister_id, .. } = create_canister(
        &env,
        ledger_id,
        account10_0.owner,
        CreateCanisterArgs {
            from_subaccount: account10_0.subaccount,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: Some(CmcCreateCanisterArgs {
                subnet_selection: None,
                settings: None,
            }),
        },
    )
    .unwrap();
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    let status = canister_status(&env, canister_id, account10_0.owner);
    assert_eq!(
        expected_balance,
        icrc1_balance_of(&env, ledger_id, account10_0)
    );
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    assert_eq!(status.settings.controllers, vec![account10_0.owner]);

    // If `CanisterSettings` do not specify a controller, the caller should still control the resulting canister
    // `creation_args` is `None`
    let CreateCanisterSuccess { canister_id, .. } = create_canister(
        &env,
        ledger_id,
        account10_0.owner,
        CreateCanisterArgs {
            from_subaccount: account10_0.subaccount,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
        },
    )
    .unwrap();
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    let status = canister_status(&env, canister_id, account10_0.owner);
    assert_eq!(
        expected_balance,
        icrc1_balance_of(&env, ledger_id, account10_0)
    );
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    assert_eq!(status.settings.controllers, vec![account10_0.owner]);

    // reject before `await`
    if let CreateCanisterError::InsufficientFunds { balance } = create_canister(
        &env,
        ledger_id,
        account10_0.owner,
        CreateCanisterArgs {
            from_subaccount: account10_0.subaccount,
            created_at_time: None,
            amount: Nat::from(u128::MAX),
            creation_args: None,
        },
    )
    .unwrap_err()
    {
        assert_eq!(balance, expected_balance);
    } else {
        panic!("wrong error")
    };

    // refund successful
    fail_next_create_canister_with(
        &env,
        cycles_ledger::endpoints::CmcCreateCanisterError::Refunded {
            refund_amount: CREATE_CANISTER_CYCLES,
            create_error: "Custom error text".to_string(),
        },
    );
    if let CreateCanisterError::FailedToCreate {
        fee_block,
        refund_block,
        error: _,
    } = create_canister(
        &env,
        ledger_id,
        account10_0.owner,
        CreateCanisterArgs {
            from_subaccount: account10_0.subaccount,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
        },
    )
    .unwrap_err()
    {
        expected_balance -= 2 * FEE;
        assert_matches!(
            get_block(&env, ledger_id, fee_block.unwrap())
                .transaction
                .operation,
            Operation::Burn {
                amount: CREATE_CANISTER_CYCLES,
                ..
            }
        );
        assert_matches!(
            get_block(&env, ledger_id, refund_block.unwrap())
                .transaction
                .operation,
            Operation::Mint {
                amount: CREATE_CANISTER_CYCLES_MINUS_FEE,
                ..
            }
        );
        assert_eq!(
            expected_balance,
            icrc1_balance_of(&env, ledger_id, account10_0)
        );
    } else {
        panic!("wrong error")
    };

    // dividing by 3 so that the number of cyles to be refunded is different from the amount of cycles consumed
    const REFUND_AMOUNT: u128 = CREATE_CANISTER_CYCLES / 3;
    const REFUND_AMOUNT_MINUS_FEE: u128 = REFUND_AMOUNT - FEE;
    fail_next_create_canister_with(
        &env,
        cycles_ledger::endpoints::CmcCreateCanisterError::Refunded {
            refund_amount: REFUND_AMOUNT,
            create_error: "Custom error text".to_string(),
        },
    );
    if let CreateCanisterError::FailedToCreate {
        fee_block,
        refund_block,
        error: _,
    } = create_canister(
        &env,
        ledger_id,
        account10_0.owner,
        CreateCanisterArgs {
            from_subaccount: account10_0.subaccount,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
        },
    )
    .unwrap_err()
    {
        expected_balance -= 2 * FEE + (CREATE_CANISTER_CYCLES - REFUND_AMOUNT);
        assert_matches!(
            get_block(&env, ledger_id, fee_block.unwrap())
                .transaction
                .operation,
            Operation::Burn {
                amount: CREATE_CANISTER_CYCLES,
                ..
            }
        );
        assert_matches!(
            get_block(&env, ledger_id, refund_block.unwrap())
                .transaction
                .operation,
            Operation::Mint {
                amount: REFUND_AMOUNT_MINUS_FEE,
                ..
            }
        );
        assert_eq!(
            expected_balance,
            icrc1_balance_of(&env, ledger_id, account10_0)
        );
    } else {
        panic!("wrong error")
    };

    // refund failed
    fail_next_create_canister_with(
        &env,
        cycles_ledger::endpoints::CmcCreateCanisterError::RefundFailed {
            create_error: "Create error text".to_string(),
            refund_error: "Refund error text".to_string(),
        },
    );
    if let CreateCanisterError::FailedToCreate {
        fee_block,
        refund_block,
        error: _,
    } = create_canister(
        &env,
        ledger_id,
        account10_0.owner,
        CreateCanisterArgs {
            from_subaccount: account10_0.subaccount,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
        },
    )
    .unwrap_err()
    {
        expected_balance -= FEE + CREATE_CANISTER_CYCLES;
        assert_matches!(
            get_block(&env, ledger_id, fee_block.unwrap())
                .transaction
                .operation,
            Operation::Burn {
                amount: CREATE_CANISTER_CYCLES,
                ..
            }
        );
        assert!(refund_block.is_none());
        assert_eq!(
            expected_balance,
            icrc1_balance_of(&env, ledger_id, account10_0)
        );
    } else {
        panic!("wrong error")
    };

    // duplicate creation request returns the same canister twice
    let arg = CreateCanisterArgs {
        from_subaccount: account10_0.subaccount,
        created_at_time: Some(env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64),
        amount: CREATE_CANISTER_CYCLES.into(),
        creation_args: None,
    };
    let canister = create_canister(&env, ledger_id, account10_0.owner, arg.clone())
        .unwrap()
        .canister_id;
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    let status = canister_status(&env, canister, account10_0.owner);
    assert_eq!(
        expected_balance,
        icrc1_balance_of(&env, ledger_id, account10_0)
    );
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    assert_eq!(vec![account10_0.owner], status.settings.controllers);
    let duplicate = create_canister(&env, ledger_id, account10_0.owner, arg).unwrap_err();
    assert_matches!(
        duplicate,
        CreateCanisterError::Duplicate { .. },
        "No duplicate reported"
    );
    let CreateCanisterError::Duplicate {
        canister_id: Some(duplicate_canister_id),
        ..
    } = duplicate
    else {
        panic!("No duplicate canister reported")
    };
    assert_eq!(
        canister, duplicate_canister_id,
        "Different canister id returned"
    )
}

// A test to check that `DuplicateError` is returned on a duplicate `create_canister` request
// and not `InsufficientFundsError` if there are not enough funds
// to execute it a second time
#[test]
fn test_create_canister_duplicate() {
    const CREATE_CANISTER_CYCLES: u128 = 1_000_000_000_000;
    let env = new_state_machine();
    install_fake_cmc(&env);
    let ledger_id = install_ledger(&env);
    let depositor_id = install_depositor(&env, ledger_id);
    let account10_0 = Account {
        owner: Principal::from_slice(&[10]),
        subaccount: Some([0; 32]),
    };
    let mut expected_balance = 1_500_000_000_000_u128;

    // make the first deposit to the user and check the result
    let deposit_res = deposit(
        &env,
        depositor_id,
        account10_0,
        expected_balance + config::FEE,
        None,
    );
    assert_eq!(deposit_res.block_index, Nat::from(0u128));
    assert_eq!(deposit_res.balance, expected_balance);
    assert_eq!(
        expected_balance,
        icrc1_balance_of(&env, ledger_id, account10_0)
    );

    let now = env
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // successful create
    let canister = create_canister(
        &env,
        ledger_id,
        account10_0.owner,
        CreateCanisterArgs {
            from_subaccount: account10_0.subaccount,
            created_at_time: Some(now),
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
        },
    )
    .unwrap()
    .canister_id;
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    let status = canister_status(&env, canister, account10_0.owner);
    assert_eq!(
        expected_balance,
        icrc1_balance_of(&env, ledger_id, account10_0)
    );
    // no canister creation fee on system subnet (where the StateMachine is by default)
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    assert_eq!(vec![account10_0.owner], status.settings.controllers);

    assert_eq!(
        CreateCanisterError::Duplicate {
            duplicate_of: Nat::from(1u128),
            canister_id: Some(canister)
        },
        create_canister(
            &env,
            ledger_id,
            account10_0.owner,
            CreateCanisterArgs {
                from_subaccount: account10_0.subaccount,
                created_at_time: Some(now),
                amount: CREATE_CANISTER_CYCLES.into(),
                creation_args: None,
            },
        )
        .unwrap_err()
    );
}

#[test]
fn test_create_canister_fail() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let account1 = account(1, None);

    let _ = env.deposit(account1, 1_000_000_000_000_000_000 + fee, None);

    let mut expected_total_supply = env.icrc1_total_supply();
    let blocks = env.get_all_blocks_with_ids();
    let balance_before_attempt = env.icrc1_balance_of(account1);
    let fee = env.icrc1_fee();

    // if refund_amount is <= env.icrc1_fee() then
    // 1. the error doesn't have the refund_block
    // 2. the user has been charged the full amount
    // 3. only one block was created
    fail_next_create_canister_with(
        &env.state_machine,
        cycles_ledger::endpoints::CmcCreateCanisterError::Refunded {
            refund_amount: 0,
            create_error: "Error while creating".to_string(),
        },
    );
    let amount = 1_000_000_000_000_000u128;
    let create_canister_result = env
        .create_canister(
            account1.owner,
            CreateCanisterArgs {
                from_subaccount: account1.subaccount,
                created_at_time: None,
                amount: Nat::from(amount),
                creation_args: None,
            },
        )
        .unwrap_err();
    assert_eq!(
        create_canister_result,
        CreateCanisterError::FailedToCreate {
            fee_block: Some(Nat::from(blocks.len())),
            refund_block: None,
            error: "Error while creating".to_string(),
        }
    );
    assert_eq!(
        balance_before_attempt - amount - fee,
        env.icrc1_balance_of(account1)
    );
    expected_total_supply -= amount + fee;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    assert_eq!(blocks.len() + 1, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash()),
            effective_fee: Some(fee),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
                operation: Operation::Burn {
                    from: account1,
                    spender: None,
                    amount,
                },
            },
        }
        .to_value(),
    };
    let blocks = blocks.into_iter().chain([burn_block]).collect::<Vec<_>>();
    assert_vec_display_eq(&blocks, env.get_all_blocks_with_ids());

    // if refund_amount is > env.icrc1_fee() then
    // 1. the error has the refund_block
    // 2. the user has been charged the fee twice
    // 3. two blocks are created
    let balance_before_attempt = env.icrc1_balance_of(account1);
    let amount = 1_000_000_000_000_000u128;
    fail_next_create_canister_with(
        &env.state_machine,
        cycles_ledger::endpoints::CmcCreateCanisterError::Refunded {
            refund_amount: amount,
            create_error: "Error while creating".to_string(),
        },
    );
    let create_canister_result = env
        .create_canister(
            account1.owner,
            CreateCanisterArgs {
                from_subaccount: account1.subaccount,
                created_at_time: None,
                amount: Nat::from(amount),
                creation_args: None,
            },
        )
        .unwrap_err();
    assert_eq!(
        create_canister_result,
        CreateCanisterError::FailedToCreate {
            fee_block: Some(Nat::from(blocks.len())),
            refund_block: Some(Nat::from(blocks.len() + 1)),
            error: "Error while creating".to_string(),
        }
    );
    assert_eq!(
        balance_before_attempt - 2 * fee,
        env.icrc1_balance_of(account1)
    );
    expected_total_supply -= 2 * fee;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    assert_eq!(blocks.len() + 2, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash()),
            effective_fee: Some(fee),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
                operation: Operation::Burn {
                    from: account1,
                    spender: None,
                    amount,
                },
            },
        }
        .to_value(),
    };
    let refund_block = BlockWithId {
        id: Nat::from(blocks.len() + 1),
        block: Block {
            phash: Some(burn_block.block.clone().hash()),
            effective_fee: Some(0),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo::from(ByteBuf::from(REFUND_MEMO))),
                operation: Operation::Mint {
                    to: account1,
                    amount: amount - fee,
                    fee: 0,
                },
            },
        }
        .to_value(),
    };
    let blocks = blocks
        .into_iter()
        .chain([burn_block, refund_block])
        .collect::<Vec<_>>();
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());
}

#[test]
fn test_create_canister_from() {
    const CREATE_CANISTER_CYCLES: u128 = 1_000_000_000_000;
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let account1 = account(1, None);
    let account1_1 = account(1, Some(1));
    let account1_2 = account(1, Some(2));
    let account1_3 = account(1, Some(3));
    let withdrawer1 = account(102, None);
    let withdrawer1_1 = account(102, Some(1));

    // make deposits to the user and check the result
    let _deposit_res = env.deposit(account1, 100 * CREATE_CANISTER_CYCLES + fee, None);
    let _deposit_res = env.deposit(account1_1, 100 * CREATE_CANISTER_CYCLES + fee, None);
    let _deposit_res = env.deposit(account1_2, 100 * CREATE_CANISTER_CYCLES + fee, None);
    let _deposit_res = env.deposit(account1_3, 100 * CREATE_CANISTER_CYCLES + fee, None);
    let mut expected_total_supply = 400 * CREATE_CANISTER_CYCLES;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // successful create
    env.icrc2_approve_or_trap(
        account1.owner,
        ApproveArgs {
            from_subaccount: None,
            spender: withdrawer1,
            amount: Nat::from(u128::MAX),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let mut expected_balance = env.icrc1_balance_of(account1);
    let mut expected_allowance = u128::MAX;
    let CreateCanisterSuccess {
        canister_id,
        block_id,
    } = env.create_canister_from_or_trap(
        withdrawer1.owner,
        CreateCanisterFromArgs {
            from: account1,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
            spender_subaccount: None,
        },
    );
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    expected_allowance -= CREATE_CANISTER_CYCLES + FEE;
    expected_total_supply -= CREATE_CANISTER_CYCLES + FEE;
    let status = env.canister_status(withdrawer1.owner, canister_id);
    assert_eq!(expected_balance, env.icrc1_balance_of(account1));
    assert_eq!(
        expected_allowance,
        env.icrc2_allowance(account1, withdrawer1).allowance
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    // no canister creation fee on system subnet (where the StateMachine is by default)
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    // If `CanisterSettings` do not specify a controller, the caller should still control the resulting canister
    assert_eq!(vec![withdrawer1.owner], status.settings.controllers);
    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(block_id.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(block_id - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the ledger. This is different from burn in
            // other ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was not set.
                created_at_time: None,
                // The memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1,
                    spender: Some(withdrawer1),
                    // The  operation amount is the withdrawn amount.
                    amount: CREATE_CANISTER_CYCLES,
                },
            },
        },
    );

    let canister_settings = CanisterSettings {
        controllers: Some(vec![account1.owner, Principal::anonymous()]),
        compute_allocation: Some(Nat::from(7_u128)),
        memory_allocation: Some(Nat::from(8_u128)),
        freezing_threshold: Some(Nat::from(9_u128)),
        reserved_cycles_limit: Some(Nat::from(10_u128)),
    };
    let CreateCanisterSuccess {
        canister_id,
        block_id,
    } = env.create_canister_from_or_trap(
        withdrawer1.owner,
        CreateCanisterFromArgs {
            from: account1,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: Some(CmcCreateCanisterArgs {
                subnet_selection: None,
                settings: Some(canister_settings.clone()),
            }),
            spender_subaccount: None,
        },
    );
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    expected_allowance -= CREATE_CANISTER_CYCLES + FEE;
    expected_total_supply -= CREATE_CANISTER_CYCLES + FEE;
    let status = env.canister_status(account1.owner, canister_id);
    assert_eq!(expected_balance, env.icrc1_balance_of(account1));
    assert_eq!(
        expected_allowance,
        env.icrc2_allowance(account1, withdrawer1).allowance
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    // order is not guaranteed
    assert_eq!(
        HashSet::<Principal>::from_iter(status.settings.controllers.iter().cloned()),
        HashSet::from_iter(canister_settings.controllers.unwrap().iter().cloned())
    );
    assert_eq!(
        status.settings.freezing_threshold,
        canister_settings.freezing_threshold.unwrap()
    );
    assert_eq!(
        status.settings.compute_allocation,
        canister_settings.compute_allocation.unwrap()
    );
    assert_eq!(
        status.settings.memory_allocation,
        canister_settings.memory_allocation.unwrap()
    );
    assert_eq!(
        status.settings.reserved_cycles_limit,
        canister_settings.reserved_cycles_limit.unwrap()
    );
    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(block_id.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(block_id - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the ledger. This is different from burn in
            // other ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was not set.
                created_at_time: None,
                // The memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1,
                    spender: Some(withdrawer1),
                    // The  operation amount is the withdrawn amount.
                    amount: CREATE_CANISTER_CYCLES,
                },
            },
        },
    );

    // create from subaccount
    env.icrc2_approve_or_trap(
        account1_1.owner,
        ApproveArgs {
            from_subaccount: account1_1.subaccount,
            spender: withdrawer1,
            amount: u128::MAX.into(),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let mut expected_balance = env.icrc1_balance_of(account1_1);
    let mut expected_allowance = u128::MAX;
    let CreateCanisterSuccess { block_id, .. } = env.create_canister_from_or_trap(
        withdrawer1.owner,
        CreateCanisterFromArgs {
            from: account1_1,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
            spender_subaccount: None,
        },
    );
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    expected_allowance -= CREATE_CANISTER_CYCLES + FEE;
    expected_total_supply -= CREATE_CANISTER_CYCLES + FEE;
    assert_eq!(expected_balance, env.icrc1_balance_of(account1_1));
    assert_eq!(
        expected_allowance,
        env.icrc2_allowance(account1_1, withdrawer1).allowance
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(block_id.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(block_id - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the ledger. This is different from burn in
            // other ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was not set.
                created_at_time: None,
                // The memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1_1,
                    spender: Some(withdrawer1),
                    // The  operation amount is the withdrawn amount.
                    amount: CREATE_CANISTER_CYCLES,
                },
            },
        },
    );

    // create from subaccount with created_at_time set
    let created_at_time = Some(env.nanos_since_epoch_u64());
    env.icrc2_approve_or_trap(
        account1_2.owner,
        ApproveArgs {
            from_subaccount: account1_2.subaccount,
            spender: withdrawer1,
            amount: u128::MAX.into(),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let mut expected_balance = env.icrc1_balance_of(account1_2);
    let mut expected_allowance = u128::MAX;
    let CreateCanisterSuccess { block_id, .. } = env.create_canister_from_or_trap(
        withdrawer1.owner,
        CreateCanisterFromArgs {
            from: account1_2,
            created_at_time,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
            spender_subaccount: None,
        },
    );
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    expected_allowance -= CREATE_CANISTER_CYCLES + FEE;
    expected_total_supply -= CREATE_CANISTER_CYCLES + FEE;
    assert_eq!(expected_balance, env.icrc1_balance_of(account1_2));
    assert_eq!(
        expected_allowance,
        env.icrc2_allowance(account1_2, withdrawer1).allowance
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(block_id.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(block_id - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the ledger. This is different from burn in
            // other ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was set.
                created_at_time,
                // The memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1_2,
                    spender: Some(withdrawer1),
                    // The  operation amount is the withdrawn amount.
                    amount: CREATE_CANISTER_CYCLES,
                },
            },
        },
    );

    // create using spender subaccount
    env.icrc2_approve_or_trap(
        account1_3.owner,
        ApproveArgs {
            from_subaccount: account1_3.subaccount,
            spender: withdrawer1_1,
            amount: u128::MAX.into(),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let mut expected_balance = env.icrc1_balance_of(account1_3);
    let mut expected_allowance = u128::MAX;
    let CreateCanisterSuccess { block_id, .. } = env.create_canister_from_or_trap(
        withdrawer1_1.owner,
        CreateCanisterFromArgs {
            from: account1_3,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
            spender_subaccount: withdrawer1_1.subaccount,
        },
    );
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    expected_allowance -= CREATE_CANISTER_CYCLES + FEE;
    expected_total_supply -= CREATE_CANISTER_CYCLES + FEE;
    assert_eq!(expected_balance, env.icrc1_balance_of(account1_3));
    assert_eq!(
        expected_allowance,
        env.icrc2_allowance(account1_3, withdrawer1_1).allowance
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(block_id.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(block_id - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the ledger. This is different from burn in
            // other ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was not set.
                created_at_time: None,
                // The memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1_3,
                    spender: Some(withdrawer1_1),
                    // The  operation amount is the withdrawn amount.
                    amount: CREATE_CANISTER_CYCLES,
                },
            },
        },
    );
}

#[test]
fn test_create_canister_from_fail() {
    const CREATE_CANISTER_CYCLES: u128 = 1_000_000_000_000;
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let withdrawer1 = account(101, None);
    let account1 = account(1, None);
    let account1_1 = account(1, Some(1));
    let account1_2 = account(1, Some(2));
    let account1_3 = account(1, Some(3));
    let account1_4 = account(1, Some(4));
    let account1_5 = account(1, Some(5));
    let account1_6 = account(1, Some(6));
    let account1_7 = account(1, Some(7));

    // make the first deposit to the user and check the result
    let _deposit_res = env.deposit(account1, CREATE_CANISTER_CYCLES / 2 + fee, None);
    let _deposit_res = env.deposit(account1_1, 100 * CREATE_CANISTER_CYCLES + fee, None);
    let _deposit_res = env.deposit(account1_2, 100 * CREATE_CANISTER_CYCLES + fee, None);
    let _deposit_res = env.deposit(account1_3, 100 * CREATE_CANISTER_CYCLES + fee, None);
    let _deposit_res = env.deposit(account1_4, 100 * CREATE_CANISTER_CYCLES + fee, None);
    let _deposit_res = env.deposit(account1_5, 100 * CREATE_CANISTER_CYCLES + fee, None);
    let _deposit_res = env.deposit(account1_6, 100 * CREATE_CANISTER_CYCLES + fee, None);
    let _deposit_res = env.deposit(account1_7, 100 * CREATE_CANISTER_CYCLES + fee, None);
    let mut expected_total_supply = env.icrc1_total_supply();

    // create with more than available in account
    env.icrc2_approve_or_trap(
        account1.owner,
        ApproveArgs {
            from_subaccount: account1.subaccount,
            spender: withdrawer1,
            amount: u128::MAX.into(),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let expected_balance = env.icrc1_balance_of(account1);
    let expected_allowance = u128::MAX;
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    let error = env
        .create_canister_from(
            withdrawer1.owner,
            CreateCanisterFromArgs {
                from: account1,
                created_at_time: None,
                amount: CREATE_CANISTER_CYCLES.into(),
                creation_args: None,
                spender_subaccount: None,
            },
        )
        .unwrap_err();
    assert_eq!(
        error,
        CreateCanisterFromError::InsufficientFunds {
            balance: expected_balance.into()
        }
    );
    assert_eq!(expected_balance, env.icrc1_balance_of(account1));
    assert_eq!(
        expected_allowance,
        env.icrc2_allowance(account1, withdrawer1).allowance
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    // check that no new block was added.
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());

    // if refund_amount is <= env.icrc1_fee() then
    // 1. the error doesn't have the refund_block
    // 2. the user has been charged the full amount
    // 3. only one block was created
    env.icrc2_approve_or_trap(
        account1_2.owner,
        ApproveArgs {
            from_subaccount: account1_2.subaccount,
            spender: withdrawer1,
            amount: u128::MAX.into(),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let mut expected_balance = env.icrc1_balance_of(account1_2);
    let mut expected_allowance = u128::MAX;
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    env.fail_next_create_canister_with(CmcCreateCanisterError::Refunded {
        refund_amount: FEE / 2,
        create_error: "Error while creating".to_string(),
    });
    let error = env
        .create_canister_from(
            withdrawer1.owner,
            CreateCanisterFromArgs {
                from: account1_2,
                created_at_time: None,
                amount: CREATE_CANISTER_CYCLES.into(),
                creation_args: None,
                spender_subaccount: None,
            },
        )
        .unwrap_err();
    assert_eq!(
        error,
        CreateCanisterFromError::FailedToCreateFrom {
            create_from_block: Some(blocks.len().into()),
            refund_block: None,
            approval_refund_block: None,
            rejection_code: RejectionCode::CanisterError,
            rejection_reason: "Error while creating".to_string(),
        }
    );
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    expected_allowance -= CREATE_CANISTER_CYCLES + FEE;
    expected_total_supply -= CREATE_CANISTER_CYCLES + FEE;
    assert_eq!(expected_balance, env.icrc1_balance_of(account1_2));
    assert_eq!(
        expected_allowance,
        env.icrc2_allowance(account1_2, withdrawer1).allowance
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    assert_eq!(blocks.len() + 1, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash()),
            effective_fee: Some(FEE),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
                operation: Operation::Burn {
                    from: account1_2,
                    spender: Some(withdrawer1),
                    amount: CREATE_CANISTER_CYCLES,
                },
            },
        }
        .to_value(),
    };
    let blocks = blocks.into_iter().chain([burn_block]).collect::<Vec<_>>();
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());

    // if env.icrc1_fee() < refund_amount < 2 * env.irc1_fee() then
    // 1. the user receives a refund
    // 2. the error contains a refund block
    // 3. the allowance does not get refunded
    env.icrc2_approve_or_trap(
        account1_3.owner,
        ApproveArgs {
            from_subaccount: account1_3.subaccount,
            spender: withdrawer1,
            amount: u128::MAX.into(),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let mut expected_balance = env.icrc1_balance_of(account1_3);
    let mut expected_allowance = u128::MAX;
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    env.fail_next_create_canister_with(CmcCreateCanisterError::Refunded {
        refund_amount: FEE + FEE / 2,
        create_error: "Error while creating".to_string(),
    });
    let error = env
        .create_canister_from(
            withdrawer1.owner,
            CreateCanisterFromArgs {
                from: account1_3,
                created_at_time: None,
                amount: CREATE_CANISTER_CYCLES.into(),
                creation_args: None,
                spender_subaccount: None,
            },
        )
        .unwrap_err();
    assert_eq!(
        error,
        CreateCanisterFromError::FailedToCreateFrom {
            create_from_block: Some(blocks.len().into()),
            refund_block: Some(Nat::from(blocks.len() + 1)),
            approval_refund_block: None,
            rejection_code: RejectionCode::CanisterError,
            rejection_reason: "Error while creating".to_string(),
        }
    );
    expected_balance -= CREATE_CANISTER_CYCLES + FEE - (FEE / 2);
    expected_allowance -= CREATE_CANISTER_CYCLES + FEE;
    expected_total_supply -= CREATE_CANISTER_CYCLES + FEE - (FEE / 2);
    assert_eq!(expected_balance, env.icrc1_balance_of(account1_3));
    assert_eq!(
        expected_allowance,
        env.icrc2_allowance(account1_3, withdrawer1).allowance
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    assert_eq!(blocks.len() + 2, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash()),
            effective_fee: Some(FEE),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
                operation: Operation::Burn {
                    from: account1_3,
                    spender: Some(withdrawer1),
                    amount: CREATE_CANISTER_CYCLES,
                },
            },
        }
        .to_value(),
    };
    let refund_block = BlockWithId {
        id: Nat::from(blocks.len() + 1),
        block: Block {
            phash: Some(burn_block.block.clone().hash()),
            effective_fee: Some(0),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo::from(ByteBuf::from(REFUND_MEMO))),
                operation: Operation::Mint {
                    to: account1_3,
                    amount: FEE / 2,
                    fee: 0,
                },
            },
        }
        .to_value(),
    };
    let blocks = blocks
        .into_iter()
        .chain([burn_block, refund_block])
        .collect::<Vec<_>>();
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());

    // if refund_amount > 2 * env.irc1_fee() then
    // 1. the user receives a refund
    // 2. the error contains a refund block
    // 3. the allowance does get refunded
    // 4. the error contains an allowance refund block
    env.icrc2_approve_or_trap(
        account1_4.owner,
        ApproveArgs {
            from_subaccount: account1_4.subaccount,
            spender: withdrawer1,
            amount: u128::MAX.into(),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let mut expected_balance = env.icrc1_balance_of(account1_4);
    let mut expected_allowance = u128::MAX;
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    env.fail_next_create_canister_with(CmcCreateCanisterError::Refunded {
        refund_amount: 2 * FEE + FEE / 2,
        create_error: "Error while creating".to_string(),
    });
    let error = env
        .create_canister_from(
            withdrawer1.owner,
            CreateCanisterFromArgs {
                from: account1_4,
                created_at_time: None,
                amount: CREATE_CANISTER_CYCLES.into(),
                creation_args: None,
                spender_subaccount: None,
            },
        )
        .unwrap_err();
    assert_eq!(
        error,
        CreateCanisterFromError::FailedToCreateFrom {
            create_from_block: Some(blocks.len().into()),
            refund_block: Some(Nat::from(blocks.len() + 1)),
            approval_refund_block: Some(Nat::from(blocks.len() + 2)),
            rejection_code: RejectionCode::CanisterError,
            rejection_reason: "Error while creating".to_string(),
        }
    );
    expected_balance -= CREATE_CANISTER_CYCLES + FEE - (FEE / 2);
    expected_allowance -= CREATE_CANISTER_CYCLES + FEE - (FEE / 2);
    expected_total_supply -= CREATE_CANISTER_CYCLES + FEE - (FEE / 2);
    assert_eq!(expected_balance, env.icrc1_balance_of(account1_4));
    assert_eq!(
        expected_allowance,
        env.icrc2_allowance(account1_4, withdrawer1).allowance
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    assert_eq!(blocks.len() + 3, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash()),
            effective_fee: Some(FEE),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
                operation: Operation::Burn {
                    from: account1_4,
                    spender: Some(withdrawer1),
                    amount: CREATE_CANISTER_CYCLES,
                },
            },
        }
        .to_value(),
    };
    let refund_block = BlockWithId {
        id: Nat::from(blocks.len() + 1),
        block: Block {
            phash: Some(burn_block.block.clone().hash()),
            effective_fee: Some(0),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo::from(ByteBuf::from(REFUND_MEMO))),
                operation: Operation::Mint {
                    to: account1_4,
                    amount: FEE + FEE / 2,
                    fee: 0,
                },
            },
        }
        .to_value(),
    };
    let approval_refund_block = BlockWithId {
        id: Nat::from(blocks.len() + 2),
        block: Block {
            phash: Some(refund_block.block.hash()),
            effective_fee: Some(env.icrc1_fee()),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                operation: Operation::Approve {
                    from: account1_4,
                    spender: withdrawer1,
                    amount: expected_allowance,
                    expected_allowance: None,
                    expires_at: None,
                    fee: None,
                },
                created_at_time: None,
                memo: Some(Memo(ByteBuf::from(PENALIZE_MEMO))),
            },
        }
        .to_value(),
    };
    let blocks = blocks
        .into_iter()
        .chain([burn_block, refund_block, approval_refund_block])
        .collect::<Vec<_>>();
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());

    // duplicate
    let created_at_time = Some(env.nanos_since_epoch_u64());
    env.icrc2_approve_or_trap(
        account1_5.owner,
        ApproveArgs {
            from_subaccount: account1_5.subaccount,
            spender: withdrawer1,
            amount: u128::MAX.into(),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let mut expected_balance = env.icrc1_balance_of(account1_5);
    let mut expected_allowance = u128::MAX;
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    let create_arg = CreateCanisterFromArgs {
        from: account1_5,
        created_at_time,
        amount: CREATE_CANISTER_CYCLES.into(),
        creation_args: None,
        spender_subaccount: None,
    };
    let CreateCanisterSuccess {
        block_id,
        canister_id,
    } = env.create_canister_from_or_trap(withdrawer1.owner, create_arg.clone());
    let error = env
        .create_canister_from(withdrawer1.owner, create_arg)
        .unwrap_err();
    assert_eq!(
        error,
        CreateCanisterFromError::Duplicate {
            duplicate_of: block_id.clone(),
            canister_id: Some(canister_id)
        }
    );
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    expected_allowance -= CREATE_CANISTER_CYCLES + FEE;
    expected_total_supply -= CREATE_CANISTER_CYCLES + FEE;
    assert_eq!(expected_balance, env.icrc1_balance_of(account1_5));
    assert_eq!(
        expected_allowance,
        env.icrc2_allowance(account1_5, withdrawer1).allowance
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    assert_eq!(blocks.len() + 1, env.number_of_blocks());
    // check that the burn block created is correct
    assert_display_eq(
        &env.get_block(block_id.clone()),
        &Block {
            // The new block parent hash is the hash of the last deposit.
            phash: Some(env.get_block(block_id - 1u8).hash()),
            // The effective fee of a burn block created by a withdrawal
            // is the fee of the ledger. This is different from burn in
            // other ledgers because the operation transfers cycles.
            effective_fee: Some(env.icrc1_fee()),
            // The timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // The created_at_time was set.
                created_at_time,
                // The memo is the canister ID receiving the cycles
                // encoded in cbor as object with a 'receiver' field marked as 0.
                memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
                // Withdrawals are recorded as burns.
                operation: Operation::Burn {
                    from: account1_5,
                    spender: Some(withdrawer1),
                    // The  operation amount is the withdrawn amount.
                    amount: CREATE_CANISTER_CYCLES,
                },
            },
        },
    );

    // approval refund does not affect expires_at
    let expires_at = Some(env.nanos_since_epoch_u64() + 100_000_000);
    env.icrc2_approve_or_trap(
        account1_6.owner,
        ApproveArgs {
            from_subaccount: account1_6.subaccount,
            spender: withdrawer1,
            amount: u128::MAX.into(),
            expected_allowance: None,
            expires_at,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let mut expected_balance = env.icrc1_balance_of(account1_6);
    let mut expected_allowance = u128::MAX;
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    env.fail_next_create_canister_with(CmcCreateCanisterError::Refunded {
        refund_amount: 2 * FEE + FEE / 2,
        create_error: "Error while creating".to_string(),
    });
    let error = env
        .create_canister_from(
            withdrawer1.owner,
            CreateCanisterFromArgs {
                from: account1_6,
                created_at_time: None,
                amount: CREATE_CANISTER_CYCLES.into(),
                creation_args: None,
                spender_subaccount: None,
            },
        )
        .unwrap_err();
    assert_eq!(
        error,
        CreateCanisterFromError::FailedToCreateFrom {
            create_from_block: Some(blocks.len().into()),
            refund_block: Some(Nat::from(blocks.len() + 1)),
            approval_refund_block: Some(Nat::from(blocks.len() + 2)),
            rejection_code: RejectionCode::CanisterError,
            rejection_reason: "Error while creating".to_string(),
        }
    );
    expected_balance -= CREATE_CANISTER_CYCLES + FEE - (FEE / 2);
    expected_allowance -= CREATE_CANISTER_CYCLES + FEE - (FEE / 2);
    expected_total_supply -= CREATE_CANISTER_CYCLES + FEE - (FEE / 2);
    assert_eq!(expected_balance, env.icrc1_balance_of(account1_6));
    assert_eq!(
        expected_allowance,
        env.icrc2_allowance(account1_6, withdrawer1).allowance
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    assert_eq!(blocks.len() + 3, env.number_of_blocks());
    let approval_refund_block = Block {
        phash: Some(env.get_block(Nat::from(blocks.len() + 1)).hash()),
        effective_fee: Some(env.icrc1_fee()),
        timestamp: env.nanos_since_epoch_u64(),
        transaction: Transaction {
            operation: Operation::Approve {
                from: account1_6,
                spender: withdrawer1,
                amount: expected_allowance,
                expected_allowance: None,
                expires_at,
                fee: None,
            },
            created_at_time: None,
            memo: Some(Memo(ByteBuf::from(PENALIZE_MEMO))),
        },
    };
    assert_eq!(
        approval_refund_block,
        env.get_block(Nat::from(blocks.len() + 2))
    );

    // refund fails
    env.icrc2_approve_or_trap(
        account1_7.owner,
        ApproveArgs {
            from_subaccount: account1_7.subaccount,
            spender: withdrawer1,
            amount: u128::MAX.into(),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    expected_total_supply -= FEE;
    let mut expected_balance = env.icrc1_balance_of(account1_7);
    let mut expected_allowance = u128::MAX;
    let blocks = env.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks;
    env.fail_next_create_canister_with(CmcCreateCanisterError::RefundFailed {
        create_error: "Error while creating".to_string(),
        refund_error: "Error while refunding".to_string(),
    });
    let error = env
        .create_canister_from(
            withdrawer1.owner,
            CreateCanisterFromArgs {
                from: account1_7,
                created_at_time: None,
                amount: CREATE_CANISTER_CYCLES.into(),
                creation_args: None,
                spender_subaccount: None,
            },
        )
        .unwrap_err();
    assert_eq!(
        error,
        CreateCanisterFromError::FailedToCreateFrom {
            create_from_block: Some(blocks.len().into()),
            refund_block: None,
            approval_refund_block: None,
            rejection_code: RejectionCode::CanisterError,
            rejection_reason:
                "create_error: Error while creating, refund error: Error while refunding"
                    .to_string(),
        }
    );
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    expected_allowance -= CREATE_CANISTER_CYCLES + FEE;
    expected_total_supply -= CREATE_CANISTER_CYCLES + FEE;
    assert_eq!(expected_balance, env.icrc1_balance_of(account1_7));
    assert_eq!(
        expected_allowance,
        env.icrc2_allowance(account1_7, withdrawer1).allowance
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    assert_eq!(blocks.len() + 1, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash()),
            effective_fee: Some(FEE),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
                operation: Operation::Burn {
                    from: account1_7,
                    spender: Some(withdrawer1),
                    amount: CREATE_CANISTER_CYCLES,
                },
            },
        }
        .to_value(),
    };
    let blocks = blocks.into_iter().chain([burn_block]).collect::<Vec<_>>();
    assert_vec_display_eq(blocks, env.get_all_blocks_with_ids());
}

#[test]
#[should_panic(expected = "memo length exceeds the maximum")]
fn test_deposit_invalid_memo() {
    let env = TestEnv::setup();

    // Attempt deposit with memo exceeding `MAX_MEMO_LENGTH`. This call should panic.
    let _res = env.deposit(
        account(1, None),
        10 * FEE,
        Some(Memo(ByteBuf::from([0; MAX_MEMO_LENGTH as usize + 1]))),
    );
}

#[test]
#[should_panic(expected = "memo length exceeds the maximum")]
fn test_icrc1_transfer_invalid_memo() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let account1 = account(1, None);
    let _deposit_res = env.deposit(account1, 1_000_000_000 + fee, None);

    // Attempt icrc1_transfer with memo exceeding `MAX_MEMO_LENGTH`. This call should panic.
    let _res = env.icrc1_transfer(
        account1.owner,
        TransferArgs {
            from_subaccount: None,
            to: account(2, None),
            fee: None,
            created_at_time: None,
            memo: Some(Memo(ByteBuf::from([0; MAX_MEMO_LENGTH as usize + 1]))),
            amount: Nat::from(100_000_u128),
        },
    );
}

#[test]
#[should_panic(expected = "memo length exceeds the maximum")]
fn test_approve_invalid_memo() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let account1 = account(1, None);
    let _deposit_res = env.deposit(account1, 1_000_000_000 + fee, None);

    // Attempt approve with memo exceeding `MAX_MEMO_LENGTH`. This call should panic.
    let _approve_res = env.icrc2_approve(
        account1.owner,
        ApproveArgs {
            from_subaccount: None,
            spender: account(2, None),
            amount: (1_000_000_000 + FEE).into(),
            expected_allowance: Some(Nat::from(0u128)),
            expires_at: None,
            fee: Some(Nat::from(FEE)),
            memo: Some(Memo(ByteBuf::from([0; MAX_MEMO_LENGTH as usize + 1]))),
            created_at_time: None,
        },
    );
}

#[test]
#[should_panic(expected = "memo length exceeds the maximum")]
fn test_icrc2_transfer_from_invalid_memo() {
    let env = TestEnv::setup();
    let fee = env.icrc1_fee();
    let account1 = account(1, None);
    let account2 = account(2, None);
    let deposit_amount = 10_000_000_000;
    let _deposit_res = env.deposit(account1, deposit_amount + fee, None);

    let _block_index = env
        .icrc2_approve(
            account1.owner,
            ApproveArgs {
                from_subaccount: account1.subaccount,
                spender: account2,
                amount: Nat::from(1_000_000_000 + FEE),
                expected_allowance: Some(Nat::from(0u64)),
                expires_at: None,
                fee: None,
                memo: None,
                created_at_time: None,
            },
        )
        .expect("Approve failed");

    // Attempt transfer_from with memo exceeding `MAX_MEMO_LENGTH`. This call should panic.
    let _transfer_from_res = env.icrc2_transfer_from(
        account2.owner,
        TransferFromArgs {
            spender_subaccount: None,
            from: account1,
            to: account2,
            amount: Nat::from(100_000_u128),
            fee: Some(Nat::from(FEE)),
            memo: Some(Memo(ByteBuf::from([0; MAX_MEMO_LENGTH as usize + 1]))),
            created_at_time: None,
        },
    );
}

#[test]
fn test_init_with_initial_balances() {
    let account1 = account(1, None);
    let account2 = account(2, None);
    let account3 = account(3, None);
    let env = TestEnv::setup_with_ledger_conf(LedgerConfig {
        initial_balances: Some(vec![
            (account1, 1_000_000_000),
            (account2, 2_000_000_000),
            (account3, 3_000_000_000),
        ]),
        ..Default::default()
    });
    assert_eq!(env.icrc1_balance_of(account1), 1_000_000_000);
    assert_eq!(env.icrc1_balance_of(account2), 2_000_000_000);
    assert_eq!(env.icrc1_balance_of(account3), 3_000_000_000);
    let block0 = get_block(&env.state_machine, env.ledger_id, Nat::from(0u8));
    if let Operation::Mint { to, amount, .. } = block0.transaction.operation {
        assert_eq!(to, account1);
        assert_eq!(amount, 1_000_000_000);
    } else {
        panic!("Expected Mint operation for block 0");
    }

    let block1 = get_block(&env.state_machine, env.ledger_id, Nat::from(1u8));
    if let Operation::Mint { to, amount, .. } = block1.transaction.operation {
        assert_eq!(to, account2);
        assert_eq!(amount, 2_000_000_000);
    } else {
        panic!("Expected Mint operation for block 1");
    }

    let block2 = get_block(&env.state_machine, env.ledger_id, Nat::from(2u8));
    if let Operation::Mint { to, amount, .. } = block2.transaction.operation {
        assert_eq!(to, account3);
        assert_eq!(amount, 3_000_000_000);
    } else {
        panic!("Expected Mint operation for block 2");
    }
}
