use std::{
    collections::{BTreeMap, HashSet},
    fmt::Display,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use assert_matches::assert_matches;
use candid::{CandidType, Decode, Encode, Nat, Principal};
use client::deposit;
use cycles_ledger::{
    config::{self, Config as LedgerConfig, FEE, MAX_MEMO_LENGTH},
    endpoints::{
        BlockWithId, ChangeIndexId, DataCertificate, DepositResult, GetBlocksResult, LedgerArgs,
        UpgradeArgs, WithdrawArgs, WithdrawError,
    },
    memo::encode_withdraw_memo,
    storage::{
        Block, Hash,
        Operation::{self, Approve, Burn, Mint, Transfer},
        Transaction, PENALIZE_MEMO,
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
use ic_cdk::api::{call::RejectionCode, management_canister::provisional::CanisterSettings};
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{
    hash_tree::{HashTreeNode, SubtreeLookupResult},
    Certificate, HashTree, LookupResult,
};
use ic_test_state_machine_client::{CallError, ErrorCode, StateMachine, WasmResult};
use icrc_ledger_types::{
    icrc::generic_metadata_value::MetadataValue,
    icrc1::{
        account::Account,
        transfer::{Memo, TransferArg as TransferArgs, TransferError},
    },
    icrc2::{
        allowance::Allowance,
        approve::{ApproveArgs, ApproveError},
        transfer_from::{TransferFromArgs, TransferFromError},
    },
};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde_bytes::ByteBuf;

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

fn get_wasm(name: &str) -> Vec<u8> {
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

fn install_fake_cmc(env: &StateMachine) {
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
}

impl TestEnv {
    fn setup() -> Self {
        let state_machine = new_state_machine();
        let ledger_id = install_ledger(&state_machine);
        let depositor_id = install_depositor(&state_machine, ledger_id);
        Self {
            state_machine,
            ledger_id,
            depositor_id,
        }
    }

    fn setup_with_ledger_conf(conf: LedgerConfig) -> Self {
        let state_machine = new_state_machine();
        let ledger_id = install_ledger_with_conf(&state_machine, conf);
        let depositor_id = install_depositor(&state_machine, ledger_id);
        Self {
            state_machine,
            ledger_id,
            depositor_id,
        }
    }

    fn upgrade_ledger(&self, args: Option<UpgradeArgs>) -> Result<(), CallError> {
        let arg = Encode!(&Some(LedgerArgs::Upgrade(args))).unwrap();
        self.state_machine
            .upgrade_canister(self.ledger_id, get_wasm("cycles-ledger"), arg, None)
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
        self.icrc3_get_blocks(vec![(u64::MIN, u64::MAX)]).blocks
    }

    fn get_block(&self, block_index: Nat) -> Block {
        client::get_block(&self.state_machine, self.ledger_id, block_index)
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

    fn withdraw(&self, caller: Principal, args: WithdrawArgs) -> Result<Nat, WithdrawError> {
        client::withdraw(&self.state_machine, self.ledger_id, caller, args)
    }

    fn withdraw_or_trap(&self, caller: Principal, args: WithdrawArgs) -> Nat {
        self.withdraw(caller, args.clone()).unwrap_or_else(|err| {
            panic!("Call to withdraw({args:?}) from caller {caller} failed with error {err:?}")
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
                    u64::from_be_bytes(last_block_index_bytes.clone().try_into().unwrap())
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

    // 0.0 Check that the total supply is 0.
    assert_eq!(env.icrc1_total_supply(), 0u128);

    // 0.1 Check that the user doesn't have any tokens before the first deposit.
    assert_eq!(env.icrc1_balance_of(account0), 0u128);

    // 1 Make the first deposit to the user and check the result.
    let deposit_res = env.deposit(account0, 1_000_000_000, None);
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
                },
            },
        },
    );

    // 2 Make another deposit to the user and check the result.
    let memo = Memo::from(vec![0xa, 0xb, 0xc, 0xd, 0xe, 0xf]);
    let deposit_res = env.deposit(account0, 500_000_000, Some(memo.clone()));
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
            phash: Some(block0.hash().unwrap()),
            // 2.2.1 effective fee of mint blocks is 0.
            effective_fee: Some(0),
            // 2.2.2 timestamp is set by the ledger.
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                // 2.2.3 transaction.created_at_time is not set.
                created_at_time: None,
                // 2.2.4 transaction.memo not set because the user set it.
                memo: Some(memo),
                // 2.2.5 transaction.operation is mint.
                operation: Operation::Mint {
                    // 2.2.6 transaction.operation.to is the user.
                    to: account0,
                    // 2.2.7 transaction.operation.amount is the deposited amount.
                    amount: 500_000_000,
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

    // check that no new block was created
    assert_eq!(Nat::from(0u8), env.number_of_blocks());
}

#[test]
fn test_withdraw_flow() {
    // TODO(SDK-1145): Add re-entrancy test

    let env = TestEnv::setup();
    let account1 = account(1, None);
    let account1_1 = account(1, Some(1));
    let account1_2 = account(1, Some(2));
    let account1_3 = account(1, Some(3));
    let account1_4 = account(1, Some(4));
    let withdraw_receiver = env.state_machine.create_canister(None);

    // make deposits to the user and check the result
    let deposit_res = env.deposit(account1, 1_000_000_000, None);
    assert_eq!(deposit_res.block_index, 0_u128);
    assert_eq!(deposit_res.balance, 1_000_000_000_u128);
    let _deposit_res = env.deposit(account1_1, 1_000_000_000, None);
    let _deposit_res = env.deposit(account1_2, 1_000_000_000, None);
    let _deposit_res = env.deposit(account1_3, 1_000_000_000, None);
    let _deposit_res = env.deposit(account1_4, 1_000_000_000, None);
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
            phash: Some(env.get_block(withdraw_idx - 1u8).hash().unwrap()),
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
            phash: Some(env.get_block(withdraw_idx - 1u8).hash().unwrap()),
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
                    // The transaction.operation.amount is the one withdrew.
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
            phash: Some(env.get_block(withdraw_idx - 1u8).hash().unwrap()),
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
    let account1 = account(1, None);
    let withdraw_receiver = env.state_machine.create_canister(None);

    // make deposits to the user and check the result
    let deposit_res = env.deposit(account1, 1_000_000_000, None);
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

    // check the last block in the ledger is still withdraw_idx
    assert_vec_display_eq(expected_blocks, env.get_all_blocks());
}

#[test]
fn test_withdraw_fails() {
    let env = TestEnv::setup();
    let account1 = account(1, None);

    // make the first deposit to the user and check the result
    let deposit_res = env.deposit(account1, 1_000_000_000_000, None);
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
    assert!(matches!(
        withdraw_result,
        WithdrawError::InsufficientFunds { balance } if balance == 1_000_000_000_000_u128
    ));
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
    assert!(matches!(
        withdraw_result,
        WithdrawError::InsufficientFunds { balance } if balance == 0_u128
    ));
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
    assert!(matches!(
        withdraw_result,
        WithdrawError::InvalidReceiver { receiver } if receiver == self_authenticating_principal
    ));
    assert_eq!(balance_before_attempt, env.icrc1_balance_of(account1));
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);
    // check that no new blocks was added.
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
    assert!(matches!(
        withdraw_result,
        WithdrawError::FailedToWithdraw {
            rejection_code: RejectionCode::DestinationInvalid,
            ..
        }
    ));
    assert_eq!(balance_before_attempt - FEE, env.icrc1_balance_of(account1));
    expected_total_supply -= FEE;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply,);
    // the destination invalid error happens after the burn block
    // was created and balances were changed. In other to fix the
    // issue, the ledger creates a mint block to refund the amount.
    // Therefore we expect two new blocks, a burn of amount + fee
    // and a mint of amount.
    assert_eq!(blocks.len() + 2, env.number_of_blocks());
    let burn_block = BlockWithId {
        id: Nat::from(blocks.len()),
        block: Block {
            phash: Some(env.get_block(Nat::from(blocks.len()) - 1u8).hash().unwrap()),
            effective_fee: Some(env.icrc1_fee()),
            timestamp: env.nanos_since_epoch_u64(),
            transaction: Transaction {
                created_at_time: None,
                memo: Some(encode_withdraw_memo(&deleted_canister)),
                operation: Operation::Burn {
                    from: account1,
                    amount: 500_000_000_u128,
                },
            },
        }
        .to_value()
        .unwrap(),
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
                    amount: 500_000_000_u128,
                },
            },
        }
        .to_value()
        .unwrap(),
    };
    let blocks = blocks
        .into_iter()
        .chain([burn_block, refund_block])
        .collect::<Vec<_>>();
    assert_vec_display_eq(&blocks, env.get_all_blocks_with_ids());

    // user keeps the cycles if they don't have enough balance to pay the fee
    let account2 = account(2, None);
    let _deposit_res = env.deposit(account2, FEE + 1, None);
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
    // check that no new blocks was added.
    assert_vec_display_eq(&blocks, env.get_all_blocks_with_ids());

    // test withdraw deduplication
    let _deposit_res = env.deposit(account2, FEE * 3, None);
    let created_at_time = env.nanos_since_epoch_u64();
    let args = WithdrawArgs {
        from_subaccount: None,
        to: env.depositor_id,
        created_at_time: Some(created_at_time),
        amount: Nat::from(FEE),
    };
    let duplicate_of = env.withdraw_or_trap(account2.owner, args.clone());
    // the same withdraw should fail because created_at_time is set and the args are the same
    assert_eq!(
        env.withdraw(account2.owner, args),
        Err(WithdrawError::Duplicate { duplicate_of })
    );
    // check that no new blocks was added.
    assert_vec_display_eq(&blocks, env.get_all_blocks_with_ids());
}

#[test]
fn test_approve_max_allowance_size() {
    let env = TestEnv::setup();
    let from = account(0, None);
    let spender = account(1, None);

    // Deposit funds
    assert_eq!(
        env.deposit(from, 1_000_000_000, None).balance,
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
fn test_approve_self() {
    let env = TestEnv::setup();
    let from = account(0, None);

    // Deposit funds
    assert_eq!(
        env.deposit(from, 1_000_000_000, None).balance,
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
fn test_approve_cap() {
    let env = TestEnv::setup();
    let from = account(0, None);
    let spender = account(1, None);

    // Deposit funds
    assert_eq!(
        env.deposit(from, 1_000_000_000, None).balance,
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
    let from = account(0, None);
    let spender = account(1, None);

    // Deposit funds
    assert_eq!(
        env.deposit(from, 1_000_000_000, None).balance,
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
    let from = account(0, None);
    let spender1 = account(1, None);
    let spender2 = account(2, None);
    let spender3 = account(3, None);

    // Deposit funds
    assert_eq!(
        env.deposit(from, 1_000_000_000, None).balance,
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
    for owner in [Principal::anonymous(), Principal::management_canister()] {
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
    }
}

#[test]
fn test_basic_transfer() {
    let env = TestEnv::setup();
    let account1 = account(1, None);
    let account2 = account(2, None);
    let deposit_amount = 1_000_000_000;
    let _deposit_res = env.deposit(account1, deposit_amount, None);
    let fee = env.icrc1_fee();
    let mut expected_total_supply = deposit_amount;

    let transfer_amount = Nat::from(100_000_u128);
    let _block_idx = env
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
        .expect("Unable to make transfer");

    assert_eq!(env.icrc1_balance_of(account2), transfer_amount.clone());
    assert_eq!(
        env.icrc1_balance_of(account1),
        Nat::from(deposit_amount) - fee - transfer_amount.clone()
    );
    expected_total_supply -= fee;
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // Should not be able to send back the full amount as the user2 cannot pay the fee
    assert_eq!(
        Err(TransferError::InsufficientFunds {
            balance: transfer_amount.clone()
        }),
        env.icrc1_transfer(
            account2.owner,
            TransferArgs {
                from_subaccount: None,
                to: account2,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
    );
    assert_eq!(env.icrc1_total_supply(), expected_total_supply);

    // Should not be able to set a fee that is incorrect
    assert_eq!(
        Err(TransferError::BadFee {
            expected_fee: Nat::from(fee)
        }),
        env.icrc1_transfer(
            account1.owner,
            TransferArgs {
                from_subaccount: None,
                to: account1,
                fee: Some(Nat::from(0_u128)),
                created_at_time: None,
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
    );

    // Should not be able to transfer from a denied principal
    for owner in [Principal::anonymous(), Principal::management_canister()] {
        env.icrc1_transfer(
            owner,
            TransferArgs {
                from_subaccount: None,
                to: account1,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
        .unwrap_err();

        env.icrc1_transfer(
            account1.owner,
            TransferArgs {
                from_subaccount: None,
                to: Account::from(owner),
                fee: None,
                created_at_time: None,
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
        .unwrap_err();

        env.icrc2_transfer_from(
            owner,
            TransferFromArgs {
                spender_subaccount: None,
                from: account1,
                to: account2,
                amount: Nat::from(0u32),
                fee: None,
                memo: None,
                created_at_time: None,
            },
        )
        .unwrap_err();
    }
}

#[test]
fn test_deduplication() {
    let env = TestEnv::setup();
    let account1 = account(1, None);
    let account2 = account(2, None);
    let deposit_amount = 1_000_000_000;
    let _deposit_res = env.deposit(account1, deposit_amount, None);
    let transfer_amount = Nat::from(100_000_u128);

    let args = TransferArgs {
        from_subaccount: None,
        to: account2,
        fee: None,
        created_at_time: None,
        memo: None,
        amount: transfer_amount.clone(),
    };

    // If created_at_time is not set, the same transaction should be able to be sent multiple times
    let _block_index = env.icrc1_transfer_or_trap(account1.owner, args.clone());
    let _block_index = env.icrc1_transfer_or_trap(account1.owner, args.clone());

    // Should not be able commit a transaction that was created in the future
    let now = env.nanos_since_epoch_u64();
    assert_eq!(
        Err(TransferError::CreatedInFuture { ledger_time: now }),
        env.icrc1_transfer(
            account1.owner,
            TransferArgs {
                created_at_time: Some(u64::MAX),
                ..args.clone()
            },
        )
    );

    // Should be able to make a transfer when created_at_time is valid
    let args = TransferArgs {
        created_at_time: Some(now),
        ..args
    };
    let block_index = env.icrc1_transfer_or_trap(account1.owner, args.clone());

    // Should not be able send the same transfer twice if created_at_time is set
    assert_eq!(
        Err(TransferError::Duplicate {
            duplicate_of: block_index
        }),
        env.icrc1_transfer(account1.owner, args.clone())
    );

    // Setting a different memo field should result in no deduplication
    env.icrc1_transfer_or_trap(
        account1.owner,
        TransferArgs {
            memo: Some(Memo(ByteBuf::from(b"1234".to_vec()))),
            ..args.clone()
        },
    );

    // Setting a different created_at_time should result in no deduplication
    env.state_machine.advance_time(Duration::from_secs(1));
    let _block_index = env
        .icrc1_transfer(
            account1.owner,
            TransferArgs {
                created_at_time: Some(now + 1),
                ..args
            },
        )
        .unwrap();
}

// A test to check that `DuplicateError` is returned on a duplicate `transfer` request
// and not `InsufficientFundsError` if there are not enough funds
// to execute it a second time
#[test]
fn test_deduplication_with_insufficient_funds() {
    let env = TestEnv::setup();
    let account1 = account(1, None);
    let account2 = account(2, None);
    let deposit_amount = 1_000_000_000;
    env.deposit(account1, deposit_amount, None);

    let now = env.nanos_since_epoch_u64();
    let args = TransferArgs {
        from_subaccount: None,
        to: account2,
        fee: None,
        created_at_time: Some(now),
        memo: None,
        amount: Nat::from(600_000_000u128),
    };
    // Make a transfer with created_at_time set
    let block_index = env.icrc1_transfer_or_trap(account1.owner, args.clone());

    // Should not be able send the same transfer twice if created_at_time is set
    assert_eq!(
        Err(TransferError::Duplicate {
            duplicate_of: block_index
        }),
        env.icrc1_transfer(account1.owner, args)
    );
}

#[test]
fn test_pruning_transactions() {
    let env = TestEnv::setup();
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
    env.deposit(account1, deposit_amount, None);

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
    let account1 = account(1, None);
    let account2 = account(2, None);

    env.deposit(account1, 2_000_000_000, None);
    env.deposit(account2, 3_000_000_000, None);
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

    let get_blocks_res = env.icrc3_get_blocks(vec![(0u64, 10u64)]);
    assert_eq!(get_blocks_res.log_length, 0_u128);
    assert_eq!(get_blocks_res.archived_blocks.len(), 0);
    assert_eq!(decode_blocks_with_ids(get_blocks_res.blocks), vec![]);

    let account1 = account(1, None);
    let account2 = account(2, None);
    let account3 = account(3, None);

    // add the first mint block
    env.deposit(account1, 5_000_000_000, None);

    let get_blocks_res = env.icrc3_get_blocks(vec![(0u64, 10u64)]);
    assert_eq!(get_blocks_res.log_length, 1_u128);
    assert_eq!(get_blocks_res.archived_blocks.len(), 0);
    let mut block0 = block(
        Mint {
            to: account1,
            amount: 5_000_000_000,
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
    env.validate_certificate(0, block0.hash().unwrap());

    // add a second mint block
    env.deposit(account2, 3_000_000_000, None);

    let get_blocks_res = env.icrc3_get_blocks(vec![(0u64, 10u64)]);
    assert_eq!(get_blocks_res.log_length, 2_u128);
    assert_eq!(get_blocks_res.archived_blocks.len(), 0);
    let mut block1 = block(
        Mint {
            to: account2,
            amount: 3_000_000_000,
        },
        None,
        None,
        Some(block0.hash().unwrap()),
    );
    let actual_blocks = decode_blocks_with_ids(get_blocks_res.blocks);
    let expected_blocks = vec![(0, block0.clone()), (1, block1.clone())];
    assert_blocks_eq_except_ts(&actual_blocks, &expected_blocks);
    // Replace the dummy timestamp in the crafted block with the real one,
    // i.e., the timestamp the ledger wrote in the real block. This is required
    // so that we can use the hash of the block as the parent hash.
    block1.timestamp = actual_blocks[1].1.timestamp;
    env.validate_certificate(1, block1.hash().unwrap());

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
            amount: 2_000_000_000,
        },
        None,
        Some(withdraw_memo),
        Some(block1.hash().unwrap()),
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
    env.validate_certificate(2, block2.hash().unwrap());

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
        Some(block2.hash().unwrap()),
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
        Some(actual_blocks[3].1.hash().unwrap()),
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
        Some(actual_blocks[4].1.hash().unwrap()),
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
    env.validate_certificate(5, block5.hash().unwrap());
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
        Burn { .. } => Some(FEE),
        Mint { .. } => Some(0),
        Transfer { fee, .. } => {
            if fee.is_none() {
                Some(FEE)
            } else {
                None
            }
        }
        Approve { fee, .. } => {
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
    });

    let account10 = account(10, None);
    let _deposit_res = env.deposit(account10, 1_000_000_000, None);
    let _deposit_res = env.deposit(account10, 2_000_000_000, None);
    let _deposit_res = env.deposit(account10, 3_000_000_000, None);
    let _deposit_res = env.deposit(account10, 4_000_000_000, None);
    let _deposit_res = env.deposit(account10, 5_000_000_000, None);

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

    let account10 = account(10, None);
    let _deposit_res = env.deposit(account10, 1_000_000_000, None);
    let _deposit_res = env.deposit(account10, 2_000_000_000, None);
    let _deposit_res = env.deposit(account10, 3_000_000_000, None);
    let _deposit_res = env.deposit(account10, 4_000_000_000, None);
    let _deposit_res = env.deposit(account10, 5_000_000_000, None);

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
    let metadata = env.icrc1_metadata();
    assert_eq!(
        metadata
            .iter()
            .find_map(|(k, v)| if k == "dfn:index_id" { Some(v) } else { None }),
        Some(&index_id.as_slice().into()),
    );
}

#[test]
fn test_change_index_id() {
    let env = TestEnv::setup();

    // by default there is no index_id set
    let metadata = env.icrc1_metadata();
    assert!(metadata.iter().all(|(k, _)| k != "dfn:index_id"));

    // set the index_id
    let index_id = Principal::from_slice(&[111]);
    let args = UpgradeArgs {
        max_blocks_per_request: None,
        change_index_id: Some(ChangeIndexId::SetTo(index_id)),
    };
    env.upgrade_ledger(Some(args)).unwrap();
    assert_eq!(
        env.icrc1_metadata()
            .iter()
            .find_map(|(k, v)| if k == "dfn:index_id" { Some(v) } else { None }),
        Some(&index_id.as_slice().into()),
    );

    // unset the index_id
    let args = UpgradeArgs {
        max_blocks_per_request: None,
        change_index_id: Some(ChangeIndexId::Unset),
    };
    env.upgrade_ledger(Some(args)).unwrap();
    let metadata = env.icrc1_metadata();
    assert!(metadata.iter().all(|(k, _)| k != "dfn:index_id"));
}

#[tokio::test]
async fn test_icrc1_test_suite() {
    let env = TestEnv::setup();
    let account10 = account(10, None);

    // make the first deposit to the user and check the result
    let deposit_res = env.deposit(account10, 1_000_000_000_000_000, None);
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
    let deposit_res = deposit(&env, depositor_id, account10_0, expected_balance, None);
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
        account10_0,
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
        account10_0,
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
        account10_0,
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

    // reject before `await`
    if let CreateCanisterError::InsufficientFunds { balance } = create_canister(
        &env,
        ledger_id,
        account10_0,
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
        account10_0,
        CreateCanisterArgs {
            from_subaccount: account10_0.subaccount,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
        },
    )
    .unwrap_err()
    {
        expected_balance -= FEE;
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
                amount: CREATE_CANISTER_CYCLES,
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
        account10_0,
        CreateCanisterArgs {
            from_subaccount: account10_0.subaccount,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
        },
    )
    .unwrap_err()
    {
        expected_balance -= FEE + (CREATE_CANISTER_CYCLES - REFUND_AMOUNT);
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
                amount: REFUND_AMOUNT,
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
        account10_0,
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
    let canister = create_canister(&env, ledger_id, account10_0, arg.clone())
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
    let duplicate = create_canister(&env, ledger_id, account10_0, arg).unwrap_err();
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
    let deposit_res = deposit(&env, depositor_id, account10_0, expected_balance, None);
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
        account10_0,
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
            account10_0,
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
    let account1 = account(1, None);
    let _deposit_res = env.deposit(account1, 1_000_000_000, None);

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
    let account1 = account(1, None);
    let _deposit_res = env.deposit(account1, 1_000_000_000, None);

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
    let account1 = account(1, None);
    let account2 = account(2, None);
    let deposit_amount = 10_000_000_000;
    let _deposit_res = env.deposit(account1, deposit_amount, None);

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
