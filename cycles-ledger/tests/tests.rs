use std::{
    collections::HashSet,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use assert_matches::assert_matches;
use candid::{CandidType, Decode, Encode, Nat, Principal};
use client::{deposit, get_metadata, get_raw_blocks, transaction_hashes, transfer, transfer_from};
use cycles_ledger::{
    config::{self, Config as LedgerConfig, FEE, MAX_MEMO_LENGTH},
    endpoints::{
        ChangeIndexId, DataCertificate, GetBlocksResult, LedgerArgs, UpgradeArgs, WithdrawArgs,
        WithdrawError,
    },
    memo::encode_withdraw_memo,
    storage::{
        Block, Hash,
        Operation::{self, Approve, Burn, Mint, Transfer},
        Transaction,
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
use gen::CyclesLedgerInMemory;
use ic_cbor::CertificateToCbor;
use ic_cdk::api::{call::RejectionCode, management_canister::provisional::CanisterSettings};
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{
    hash_tree::{HashTreeNode, SubtreeLookupResult},
    Certificate, HashTree, LookupResult,
};
use ic_test_state_machine_client::{ErrorCode, StateMachine, WasmResult};
use icrc_ledger_types::{
    icrc1::{
        account::Account,
        transfer::TransferArg as TransferArgs,
        transfer::{Memo, TransferError},
    },
    icrc2::{
        approve::{ApproveArgs, ApproveError},
        transfer_from::{TransferFromArgs, TransferFromError},
    },
};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde_bytes::ByteBuf;

use crate::{
    client::{
        approve, balance_of, canister_status, create_canister, fail_next_create_canister_with, fee,
        get_allowance, get_block, get_tip_certificate, total_supply, transaction_timestamps,
        withdraw,
    },
    gen::{CyclesLedgerInStateMachine, IsCyclesLedger},
};

mod client;
mod gen;

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
        subaccount: subaccount
            .map(|subaccount| subaccount.to_be_bytes().as_slice().try_into().unwrap()),
    }
}

#[test]
fn test_deposit_flow() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user = account(0, None);

    // 0.0 Check that the total supply is 0.
    assert_eq!(total_supply(env, ledger_id), 0u128);

    // 0.1 Check that the user doesn't have any tokens before the first deposit.
    assert_eq!(balance_of(env, ledger_id, user), 0u128);

    // 1 Make the first deposit to the user and check the result.
    let deposit_res = deposit(env, depositor_id, user, 1_000_000_000, None);
    assert_eq!(deposit_res.block_index, Nat::from(0_u128));
    assert_eq!(deposit_res.balance, Nat::from(1_000_000_000_u128));

    // 1.0 Check that the right amount of tokens have been minted.
    assert_eq!(total_supply(env, ledger_id), 1_000_000_000);

    // 1.1 Check that the user has the right balance.
    assert_eq!(balance_of(env, ledger_id, user), 1_000_000_000);

    // 1.2 Check that the block created is correct
    let block0 = get_block(env, ledger_id, deposit_res.block_index);
    // 1.2.0 first block has no parent hash.
    assert_eq!(block0.phash, None);
    // 1.2.1 effective fee of mint blocks is 0.
    assert_eq!(block0.effective_fee, Some(0));
    // 1.2.2 timestamp is set by the ledger.
    assert_eq!(
        block0.timestamp as u128,
        env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    );
    // 1.2.3 transaction.created_at_time is not set.
    assert_eq!(block0.transaction.created_at_time, None);
    // 1.2.4 transaction.memo is not set because the user didn't set it.
    assert_eq!(block0.transaction.memo, None);
    // 1.2.5 transaction.operation is mint
    if let Operation::Mint { to, amount } = block0.transaction.operation {
        // 1.2.6 transaction.operation.to is the user.
        assert_eq!(to, user);
        // 1.2.7 transaction.operation.amount is the one deposited.
        assert_eq!(amount, 1_000_000_000);
    } else {
        panic!("deposit shoult create a mint block, found {:?}", block0);
    };

    // 2 Make another deposit to the user and check the result.
    let memo = Memo::from(vec![0xa, 0xb, 0xc, 0xd, 0xe, 0xf]);
    let deposit_res = deposit(env, depositor_id, user, 500_000_000, Some(memo.clone()));
    assert_eq!(deposit_res.block_index, Nat::from(1_u128));
    assert_eq!(deposit_res.balance, Nat::from(1_500_000_000_u128));

    // 2.0 Check that the right amount of tokens have been minted
    assert_eq!(total_supply(env, ledger_id), 1_500_000_000);

    // 2.1 Check that the user has the right balance after both deposits.
    assert_eq!(balance_of(env, ledger_id, user), 1_500_000_000);

    // 2.2 Check that the block created is correct
    let block1 = get_block(env, ledger_id, deposit_res.block_index);
    // 2.2.0 second block has the first block hash as parent hash.
    assert_eq!(block1.phash, Some(block0.hash().unwrap()));
    // 2.2.1 effective fee of mint blocks is 0.
    assert_eq!(block1.effective_fee, Some(0));
    // 2.2.2 timestamp is set by the ledger.
    assert_eq!(
        block1.timestamp as u128,
        env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    );
    // 2.2.3 transaction.created_at_time is not set.
    assert_eq!(block1.transaction.created_at_time, None);
    // 2.2.4 transaction.memo not set because the user set it.
    assert_eq!(block1.transaction.memo, Some(memo));
    // 2.2.5 transaction.operation is mint
    if let Operation::Mint { to, amount } = block1.transaction.operation {
        // 2.2.6 transaction.operation.to is the user.
        assert_eq!(to, user);
        // 2.2.7 transaction.operation.amount is the one deposited.
        assert_eq!(amount, 500_000_000);
    } else {
        panic!("deposit shoult create a mint block, found {:?}", block1);
    };
}

#[test]
#[should_panic]
fn test_deposit_amount_below_fee() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };

    // Attempt to deposit fewer than [config::FEE] cycles. This call should panic.
    let _deposit_result = deposit(env, depositor_id, user, config::FEE - 1, None);
}

#[test]
fn test_withdraw_flow() {
    // TODO(SDK-1145): Add re-entrancy test

    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user_main_account = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };
    let user_subaccount_1 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: Some([1; 32]),
    };
    let user_subaccount_2 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: Some([2; 32]),
    };
    let user_subaccount_3 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: Some([3; 32]),
    };
    let user_subaccount_4 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: Some([4; 32]),
    };
    let withdraw_receiver = env.create_canister(None);

    // make deposits to the user and check the result
    let deposit_res = deposit(env, depositor_id, user_main_account, 1_000_000_000, None);
    assert_eq!(deposit_res.block_index, 0_u128);
    assert_eq!(deposit_res.balance, 1_000_000_000_u128);
    deposit(env, depositor_id, user_subaccount_1, 1_000_000_000, None);
    deposit(env, depositor_id, user_subaccount_2, 1_000_000_000, None);
    deposit(env, depositor_id, user_subaccount_3, 1_000_000_000, None);
    deposit(env, depositor_id, user_subaccount_4, 1_000_000_000, None);
    let mut expected_total_supply = 5_000_000_000;
    assert_eq!(total_supply(env, ledger_id), expected_total_supply);

    // withdraw cycles from main account
    let withdraw_receiver_balance = env.cycle_balance(withdraw_receiver);
    let withdraw_amount = 500_000_000_u128;
    let _withdraw_idx = withdraw(
        env,
        ledger_id,
        user_main_account,
        WithdrawArgs {
            from_subaccount: None,
            to: withdraw_receiver,
            created_at_time: None,
            amount: Nat::from(withdraw_amount),
        },
    )
    .unwrap();
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.cycle_balance(withdraw_receiver)
    );
    assert_eq!(
        balance_of(env, ledger_id, user_main_account),
        1_000_000_000 - withdraw_amount - FEE
    );
    expected_total_supply -= withdraw_amount + FEE;
    assert_eq!(total_supply(env, ledger_id), expected_total_supply);

    // withdraw cycles from subaccount
    let withdraw_receiver_balance = env.cycle_balance(withdraw_receiver);
    let withdraw_amount = 100_000_000_u128;
    let _withdraw_idx = withdraw(
        env,
        ledger_id,
        user_subaccount_1,
        WithdrawArgs {
            from_subaccount: Some(*user_subaccount_1.effective_subaccount()),
            to: withdraw_receiver,
            created_at_time: None,
            amount: Nat::from(withdraw_amount),
        },
    )
    .unwrap();
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.cycle_balance(withdraw_receiver)
    );
    assert_eq!(
        balance_of(env, ledger_id, user_subaccount_1),
        1_000_000_000 - withdraw_amount - FEE
    );
    expected_total_supply -= withdraw_amount + FEE;
    assert_eq!(total_supply(env, ledger_id), expected_total_supply);

    // withdraw cycles from subaccount with created_at_time set
    let now = env
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let withdraw_receiver_balance = env.cycle_balance(withdraw_receiver);
    let withdraw_amount = 300_000_000_u128;
    let _withdraw_idx = withdraw(
        env,
        ledger_id,
        user_subaccount_3,
        WithdrawArgs {
            from_subaccount: Some(*user_subaccount_3.effective_subaccount()),
            to: withdraw_receiver,
            created_at_time: Some(now),
            amount: Nat::from(withdraw_amount),
        },
    )
    .unwrap();
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.cycle_balance(withdraw_receiver)
    );
    assert_eq!(
        balance_of(env, ledger_id, user_subaccount_3),
        1_000_000_000 - withdraw_amount - FEE
    );
    expected_total_supply -= withdraw_amount + FEE;
    assert_eq!(total_supply(env, ledger_id), expected_total_supply);
}

// A test to check that `DuplicateError` is returned on a duplicate `withdraw` request
// and not `InsufficientFundsError`, in case when there is not enough funds
// to execute it a second time
#[test]
fn test_withdraw_duplicate() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user_main_account = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };
    let withdraw_receiver = env.create_canister(None);

    // make deposits to the user and check the result
    let deposit_res = deposit(env, depositor_id, user_main_account, 1_000_000_000, None);
    assert_eq!(deposit_res.block_index, 0_u128);
    assert_eq!(deposit_res.balance, 1_000_000_000_u128);

    let now = env
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // withdraw cycles from main account
    let withdraw_receiver_balance = env.cycle_balance(withdraw_receiver);
    let withdraw_amount = 900_000_000_u128;
    let withdraw_idx = withdraw(
        env,
        ledger_id,
        user_main_account,
        WithdrawArgs {
            from_subaccount: None,
            to: withdraw_receiver,
            created_at_time: Some(now),
            amount: Nat::from(withdraw_amount),
        },
    )
    .unwrap();
    assert_eq!(
        withdraw_receiver_balance + withdraw_amount,
        env.cycle_balance(withdraw_receiver)
    );
    assert_eq!(
        balance_of(env, ledger_id, user_main_account),
        1_000_000_000 - withdraw_amount - FEE
    );

    assert_eq!(
        WithdrawError::Duplicate {
            duplicate_of: withdraw_idx
        },
        withdraw(
            env,
            ledger_id,
            user_main_account,
            WithdrawArgs {
                from_subaccount: None,
                to: withdraw_receiver,
                created_at_time: Some(now),
                amount: Nat::from(withdraw_amount),
            },
        )
        .unwrap_err()
    );
}

#[test]
fn test_withdraw_fails() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };

    // make the first deposit to the user and check the result
    let deposit_res = deposit(env, depositor_id, user, 1_000_000_000_000, None);
    assert_eq!(deposit_res.block_index, Nat::from(0_u128));
    assert_eq!(deposit_res.balance, 1_000_000_000_000_u128);

    // withdraw more than available
    let balance_before_attempt = balance_of(env, ledger_id, user);
    let withdraw_result = withdraw(
        env,
        ledger_id,
        user,
        WithdrawArgs {
            from_subaccount: None,
            to: depositor_id,
            created_at_time: None,
            amount: Nat::from(u128::MAX),
        },
    )
    .unwrap_err();
    assert!(matches!(
        withdraw_result,
        WithdrawError::InsufficientFunds { balance } if balance == 1_000_000_000_000_u128
    ));
    assert_eq!(balance_before_attempt, balance_of(env, ledger_id, user));
    let mut expected_total_supply = 1_000_000_000_000;
    assert_eq!(total_supply(env, ledger_id), expected_total_supply,);

    // withdraw from empty subaccount
    let withdraw_result = withdraw(
        env,
        ledger_id,
        user,
        WithdrawArgs {
            from_subaccount: Some([5; 32]),
            to: depositor_id,
            created_at_time: None,
            amount: Nat::from(100_000_000_u128),
        },
    )
    .unwrap_err();
    assert!(matches!(
        withdraw_result,
        WithdrawError::InsufficientFunds { balance } if balance == 0_u128
    ));
    assert_eq!(total_supply(env, ledger_id), expected_total_supply,);

    // withdraw cycles to user instead of canister
    let balance_before_attempt = balance_of(env, ledger_id, user);
    let self_authenticating_principal = candid::Principal::from_text(
        "luwgt-ouvkc-k5rx5-xcqkq-jx5hm-r2rj2-ymqjc-pjvhb-kij4p-n4vms-gqe",
    )
    .unwrap();
    let withdraw_result = withdraw(
        env,
        ledger_id,
        user,
        WithdrawArgs {
            from_subaccount: None,
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
    assert_eq!(balance_before_attempt, balance_of(env, ledger_id, user));
    assert_eq!(total_supply(env, ledger_id), expected_total_supply,);

    // withdraw cycles to deleted canister
    let balance_before_attempt = balance_of(env, ledger_id, user);
    let deleted_canister = env.create_canister(None);
    env.stop_canister(deleted_canister, None).unwrap();
    env.delete_canister(deleted_canister, None).unwrap();
    let withdraw_result = withdraw(
        env,
        ledger_id,
        user,
        WithdrawArgs {
            from_subaccount: None,
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
    assert_eq!(
        balance_before_attempt - FEE,
        balance_of(env, ledger_id, user)
    );
    expected_total_supply -= FEE;
    assert_eq!(total_supply(env, ledger_id), expected_total_supply,);

    // user keeps the cycles if they don't have enough balance to pay the fee
    let user_2 = Account {
        owner: Principal::from_slice(&[2]),
        subaccount: None,
    };
    deposit(env, depositor_id, user_2, FEE + 1, None);
    withdraw(
        env,
        ledger_id,
        user_2,
        WithdrawArgs {
            from_subaccount: None,
            to: depositor_id,
            created_at_time: None,
            amount: Nat::from(u128::MAX),
        },
    )
    .unwrap_err();
    assert_eq!(FEE + 1, balance_of(env, ledger_id, user_2));
    withdraw(
        env,
        ledger_id,
        user_2,
        WithdrawArgs {
            from_subaccount: None,
            to: depositor_id,
            created_at_time: None,
            amount: Nat::from(u128::MAX),
        },
    )
    .unwrap_err();
    assert_eq!(FEE + 1, balance_of(env, ledger_id, user_2));

    // test withdraw deduplication
    deposit(env, depositor_id, user_2, FEE * 3, None);
    let created_at_time = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let args = WithdrawArgs {
        from_subaccount: None,
        to: depositor_id,
        created_at_time: Some(created_at_time),
        amount: Nat::from(FEE),
    };
    let duplicate_of = withdraw(env, ledger_id, user_2, args.clone()).unwrap();
    // the same withdraw should fail because created_at_time is set and the args are the same
    assert_eq!(
        withdraw(env, ledger_id, user_2, args),
        Err(WithdrawError::Duplicate { duplicate_of })
    );
}

fn system_time_to_nanos(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as u64
}

#[test]
fn test_approve_max_allowance_size() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let from = Account {
        owner: Principal::from_slice(&[0]),
        subaccount: None,
    };
    let spender = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };

    // Deposit funds
    assert_eq!(
        deposit(env, depositor_id, from, 1_000_000_000, None).balance,
        1_000_000_000_u128
    );

    // Largest possible allowance in terms of size in bytes - max amount and expiration
    let block_index = approve(
        env,
        ledger_id,
        from,
        spender,
        u128::MAX,
        None,
        Some(u64::MAX),
    )
    .expect("approve failed");
    assert_eq!(block_index, 1_u128);
    let allowance = get_allowance(env, ledger_id, from, spender);
    assert_eq!(allowance.allowance, Nat::from(u128::MAX));
    assert_eq!(allowance.expires_at, Some(u64::MAX));
    assert_eq!(
        balance_of(env, ledger_id, from),
        Nat::from(1_000_000_000 - FEE)
    );
}

#[test]
fn test_approve_self() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let from = Account {
        owner: Principal::from_slice(&[0]),
        subaccount: None,
    };

    // Deposit funds
    assert_eq!(
        deposit(env, depositor_id, from, 1_000_000_000, None).balance,
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
        .update_call(
            ledger_id,
            from.owner,
            "icrc2_approve",
            Encode!(&args).unwrap(),
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::CanisterCalledTrap);
    assert!(err.description.ends_with("self approval is not allowed"));
    assert_eq!(balance_of(env, ledger_id, from), 1_000_000_000);
    assert_eq!(total_supply(env, ledger_id), 1_000_000_000);
}

#[test]
fn test_approve_cap() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let from = Account {
        owner: Principal::from_slice(&[0]),
        subaccount: None,
    };
    let spender = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };

    // Deposit funds
    assert_eq!(
        deposit(env, depositor_id, from, 1_000_000_000, None).balance,
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
    env.update_call(
        ledger_id,
        from.owner,
        "icrc2_approve",
        Encode!(&args).unwrap(),
    )
    .unwrap();
    let allowance = get_allowance(env, ledger_id, from, spender);
    assert_eq!(allowance.allowance, Nat::from(u128::MAX));
    assert_eq!(allowance.expires_at, None);
    assert_eq!(
        balance_of(env, ledger_id, from),
        Nat::from(1_000_000_000 - FEE)
    );
}

// A test to check that `DuplicateError` is returned on a duplicate `approve` request
// and not `UnexpectedAllowanceError` if `expected_allowance` is set
#[test]
fn test_approve_duplicate() {
    use icrc_ledger_types::icrc2::approve::ApproveError;
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let from = Account {
        owner: Principal::from_slice(&[0]),
        subaccount: None,
    };
    let spender = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };

    // Deposit funds
    assert_eq!(
        deposit(env, depositor_id, from, 1_000_000_000, None).balance,
        1_000_000_000u128
    );

    let now = env
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
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
    env.update_call(
        ledger_id,
        from.owner,
        "icrc2_approve",
        Encode!(&args).unwrap(),
    )
    .unwrap();
    let allowance = get_allowance(env, ledger_id, from, spender);
    assert_eq!(allowance.allowance, Nat::from(100u128));
    assert_eq!(allowance.expires_at, None);
    assert_eq!(
        balance_of(env, ledger_id, from),
        Nat::from(1_000_000_000 - FEE)
    );

    // re-submit should error with duplicate
    env.update_call(
        ledger_id,
        from.owner,
        "icrc2_approve",
        Encode!(&args).unwrap(),
    )
    .unwrap();

    let result = if let WasmResult::Reply(res) = env
        .update_call(
            ledger_id,
            from.owner,
            "icrc2_approve",
            Encode!(&args).unwrap(),
        )
        .unwrap()
    {
        Decode!(&res, Result<Nat, ApproveError>).unwrap()
    } else {
        panic!("icrc2_approve rejected")
    };

    assert_eq!(
        result,
        Err(ApproveError::Duplicate {
            duplicate_of: Nat::from(1u128)
        })
    );
}

#[test]
fn test_approval_expiring() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let from = Account {
        owner: Principal::from_slice(&[0]),
        subaccount: None,
    };
    let spender1 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };
    let spender2 = Account {
        owner: Principal::from_slice(&[2]),
        subaccount: None,
    };
    let spender3 = Account {
        owner: Principal::from_slice(&[3]),
        subaccount: None,
    };

    // Deposit funds
    assert_eq!(
        deposit(env, depositor_id, from, 1_000_000_000, None).balance,
        1_000_000_000_u128
    );

    // First approval expiring 1 hour from now.
    let expiration = system_time_to_nanos(env.time()) + Duration::from_secs(3600).as_nanos() as u64;
    let block_index = approve(
        env,
        ledger_id,
        from,
        spender1,
        100_000_000_u128,
        None,
        Some(expiration),
    )
    .expect("approve failed");
    assert_eq!(block_index, 1_u128);
    let allowance = get_allowance(env, ledger_id, from, spender1);
    assert_eq!(allowance.allowance, Nat::from(100_000_000_u128));
    assert_eq!(allowance.expires_at, Some(expiration));

    // Second approval expiring 3 hour from now.
    let expiration_3h =
        system_time_to_nanos(env.time()) + Duration::from_secs(3 * 3600).as_nanos() as u64;
    let block_index = approve(
        env,
        ledger_id,
        from,
        spender2,
        200_000_000_u128,
        None,
        Some(expiration_3h),
    )
    .expect("approve failed");
    assert_eq!(block_index, 2_u128);
    let allowance = get_allowance(env, ledger_id, from, spender2);
    assert_eq!(allowance.allowance, Nat::from(200_000_000_u128));
    assert_eq!(allowance.expires_at, Some(expiration_3h));

    // Test expired approval pruning, advance time 2 hours.
    env.advance_time(Duration::from_secs(2 * 3600));
    env.tick();

    // Add additional approval to trigger expired approval pruning
    approve(
        env,
        ledger_id,
        from,
        spender3,
        300_000_000_u128,
        None,
        Some(expiration_3h),
    )
    .expect("approve failed");
    let allowance = get_allowance(env, ledger_id, from, spender3);
    assert_eq!(allowance.allowance, Nat::from(300_000_000_u128));
    assert_eq!(allowance.expires_at, Some(expiration_3h));

    let allowance = get_allowance(env, ledger_id, from, spender1);
    assert_eq!(allowance.allowance, Nat::from(0_u128));
    assert_eq!(allowance.expires_at, None);
    let allowance = get_allowance(env, ledger_id, from, spender2);
    assert_eq!(allowance.allowance, Nat::from(200_000_000_u128));
    assert_eq!(allowance.expires_at, Some(expiration_3h));

    // Should not be able to approve from/to a denied principal
    for owner in [Principal::anonymous(), Principal::management_canister()] {
        approve(
            env,
            ledger_id,
            Account::from(owner),
            spender1,
            100_000_000u128,
            None,
            None,
        )
        .unwrap_err();
        approve(
            env,
            ledger_id,
            from,
            Account::from(owner),
            100_000_000u128,
            None,
            None,
        )
        .unwrap_err();
    }
}

#[test]
fn test_basic_transfer() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user1 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };
    let user2: Account = Account {
        owner: Principal::from_slice(&[2]),
        subaccount: None,
    };
    let deposit_amount = 1_000_000_000;
    deposit(env, depositor_id, user1, deposit_amount, None);
    let fee = fee(env, ledger_id);
    let mut expected_total_supply = deposit_amount;

    let transfer_amount = Nat::from(100_000_u128);
    transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: transfer_amount.clone(),
        },
    )
    .unwrap();

    assert_eq!(balance_of(env, ledger_id, user2), transfer_amount.clone());
    assert_eq!(
        balance_of(env, ledger_id, user1),
        Nat::from(deposit_amount) - fee.clone() - transfer_amount.clone()
    );
    expected_total_supply -= fee.0.to_u128().unwrap();
    assert_eq!(total_supply(env, ledger_id), expected_total_supply);

    // Should not be able to send back the full amount as the user2 cannot pay the fee
    assert_eq!(
        TransferError::InsufficientFunds {
            balance: transfer_amount.clone()
        },
        transfer(
            env,
            ledger_id,
            user2.owner,
            TransferArgs {
                from_subaccount: None,
                to: user2,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
        .unwrap_err()
    );
    assert_eq!(total_supply(env, ledger_id), expected_total_supply);

    // Should not be able to set a fee that is incorrect
    assert_eq!(
        TransferError::BadFee {
            expected_fee: fee.clone()
        },
        transfer(
            env,
            ledger_id,
            user1.owner,
            TransferArgs {
                from_subaccount: None,
                to: user1,
                fee: Some(Nat::from(0_u128)),
                created_at_time: None,
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
        .unwrap_err()
    );

    // Should not be able to transfer from a denied principal
    for owner in [Principal::anonymous(), Principal::management_canister()] {
        transfer(
            env,
            ledger_id,
            owner,
            TransferArgs {
                from_subaccount: None,
                to: user1,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
        .unwrap_err();

        transfer(
            env,
            ledger_id,
            user1.owner,
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

        transfer_from(env, ledger_id, user1, user2, Account::from(owner), 0).unwrap_err();
    }
}

#[test]
fn test_deduplication() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user1 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };
    let user2: Account = Account {
        owner: Principal::from_slice(&[2]),
        subaccount: None,
    };
    let deposit_amount = 1_000_000_000;
    deposit(env, depositor_id, user1, deposit_amount, None);
    let transfer_amount = Nat::from(100_000_u128);

    // If created_at_time is not set, the same transaction should be able to be sent multiple times
    transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: transfer_amount.clone(),
        },
    )
    .unwrap();

    transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: transfer_amount.clone(),
        },
    )
    .unwrap();

    // Should not be able commit a transaction that was created in the future
    let mut now = env
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    assert_eq!(
        TransferError::CreatedInFuture { ledger_time: now },
        transfer(
            env,
            ledger_id,
            user1.owner,
            TransferArgs {
                from_subaccount: None,
                to: user1,
                fee: None,
                created_at_time: Some(u64::MAX),
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
        .unwrap_err()
    );

    // Should be able to make a transfer when created_at_time is valid
    let tx: Nat = transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: Some(now),
            memo: None,
            amount: transfer_amount.clone(),
        },
    )
    .unwrap();

    // Should not be able send the same transfer twice if created_at_time is set
    assert_eq!(
        TransferError::Duplicate { duplicate_of: tx },
        transfer(
            env,
            ledger_id,
            user1.owner,
            TransferArgs {
                from_subaccount: None,
                to: user2,
                fee: None,
                created_at_time: Some(now),
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
        .unwrap_err()
    );

    // Setting a different memo field should result in no deduplication
    transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: Some(now),
            memo: Some(Memo(ByteBuf::from(b"1234".to_vec()))),
            amount: transfer_amount.clone(),
        },
    )
    .unwrap();

    // Advance time so that the deduplication window is shifted
    env.advance_time(Duration::from_secs(1));
    now = env
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Now the transfer which was deduplicated previously should be ok
    transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: Some(now),
            memo: None,
            amount: transfer_amount.clone(),
        },
    )
    .unwrap();
}

// A test to check that `DuplicateError` is returned on a duplicate `transfer` request
// and not `InsufficientFundsError` if there are not enough funds
// to execute it a second time
#[test]
fn test_deduplication_with_insufficient_funds() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user1 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };
    let user2: Account = Account {
        owner: Principal::from_slice(&[2]),
        subaccount: None,
    };
    let deposit_amount = 1_000_000_000;
    deposit(env, depositor_id, user1, deposit_amount, None);
    let transfer_amount = Nat::from(600_000_000u128);

    let now = env
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // Make a transfer with created_at_time set
    let tx: Nat = transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: Some(now),
            memo: None,
            amount: transfer_amount.clone(),
        },
    )
    .unwrap();

    // Should not be able send the same transfer twice if created_at_time is set
    assert_eq!(
        TransferError::Duplicate { duplicate_of: tx },
        transfer(
            env,
            ledger_id,
            user1.owner,
            TransferArgs {
                from_subaccount: None,
                to: user2,
                fee: None,
                created_at_time: Some(now),
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
        .unwrap_err()
    );
}

#[test]
fn test_pruning_transactions() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user1 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };
    let user2 = Account {
        owner: Principal::from_slice(&[2]),
        subaccount: None,
    };
    let transfer_amount = Nat::from(100_000_u128);

    let check_tx_hashes = |length: u64, first_block: u64, last_block: u64| {
        let tx_hashes = transaction_hashes(env, ledger_id);
        let mut idxs: Vec<&u64> = tx_hashes.values().collect::<Vec<&u64>>();
        idxs.sort();
        assert_eq!(idxs.len() as u64, length);
        assert_eq!(*idxs[0], first_block);
        assert_eq!(*idxs[idxs.len() - 1], last_block);
    };
    let check_tx_timestamps =
        |length: u64, first_timestamp: (u64, u64), last_timestamp: (u64, u64)| {
            let tx_timestamps = transaction_timestamps(env, ledger_id);
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

    let tx_hashes = transaction_hashes(env, ledger_id);
    // There have not been any transactions. The transaction hashes log should be empty
    assert!(tx_hashes.is_empty());

    let deposit_amount = 100_000_000_000;
    deposit(env, depositor_id, user1, deposit_amount, None);

    // A deposit does not have a `created_at_time` argument and is therefore not recorded
    let tx_hashes = transaction_hashes(env, ledger_id);
    assert!(tx_hashes.is_empty());

    // Create a transfer where `created_at_time` is not set
    transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: transfer_amount.clone(),
        },
    )
    .unwrap();

    // There should not be an entry for deduplication
    let tx_hashes = transaction_hashes(env, ledger_id);
    assert!(tx_hashes.is_empty());

    let time = env
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // Create a transfer with `created_at_time` set
    let transfer_idx_2 = transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
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
    check_tx_hashes(1, transfer_idx_2, transfer_idx_2);
    check_tx_timestamps(1, (time, transfer_idx_2), (time, transfer_idx_2));

    // Create another transaction with the same timestamp but a different hash
    let transfer_idx_3 = transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
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
    check_tx_hashes(2, transfer_idx_2, transfer_idx_3);
    check_tx_timestamps(2, (time, transfer_idx_2), (time, transfer_idx_3));

    // Advance time to move the Transaction window
    env.advance_time(Duration::from_nanos(
        config::TRANSACTION_WINDOW.as_nanos() as u64
            + config::PERMITTED_DRIFT.as_nanos() as u64 * 2,
    ));
    env.tick();
    let time = env
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // Create another transaction to trigger pruning
    let transfer_idx_4 = transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
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
    check_tx_hashes(1, transfer_idx_4, transfer_idx_4);
    check_tx_timestamps(1, (time, transfer_idx_4), (time, transfer_idx_4));
}

#[test]
fn test_total_supply_after_upgrade() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user1 = Account::from(Principal::from_slice(&[1]));
    let user2 = Account::from(Principal::from_slice(&[2]));

    deposit(env, depositor_id, user1, 2_000_000_000, None);
    deposit(env, depositor_id, user2, 3_000_000_000, None);
    let fee = fee(env, ledger_id);
    transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(1_000_000_000_u128),
        },
    )
    .unwrap();
    withdraw(
        env,
        ledger_id,
        user2,
        WithdrawArgs {
            from_subaccount: None,
            to: depositor_id,
            created_at_time: None,
            amount: Nat::from(1_000_000_000_u128),
        },
    )
    .unwrap();

    // total_supply should be 5m - 1m sent back to the depositor - twice the fee for transfer and withdraw
    let expected_total_supply = 5_000_000_000 - 1_000_000_000 - 2 * fee.0.to_u128().unwrap();
    assert_eq!(total_supply(env, ledger_id), expected_total_supply);
    let upgrade_args = Encode!(&None::<LedgerArgs>).unwrap();
    env.upgrade_canister(ledger_id, get_wasm("cycles-ledger"), upgrade_args, None)
        .unwrap();
    assert_eq!(total_supply(env, ledger_id), expected_total_supply);
}

// Validate that the given [response_certificate], [last_block_index], and [last_block_hash]
// match the certified data from the ledger
#[track_caller]
fn validate_certificate(
    env: &StateMachine,
    ledger_id: Principal,
    last_block_index: u64,
    last_block_hash: Hash,
) {
    let DataCertificate {
        certificate,
        hash_tree,
    } = get_tip_certificate(env, ledger_id);
    let certificate = Certificate::from_cbor(certificate.as_slice()).unwrap();
    assert_matches!(
        certificate.verify(ledger_id.as_slice(), &env.root_key()),
        Ok(_)
    );

    let certified_data_path: [&[u8]; 3] = [
        "canister".as_bytes(),
        ledger_id.as_slice(),
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

#[test]
fn test_icrc3_get_blocks() {
    // Utility to extract all IDs and the corresponding blcks from the given [GetBlocksResult].
    let get_txs = |res: &GetBlocksResult| -> Vec<(u64, Block)> {
        res.blocks
            .iter()
            .map(|b| {
                let block_id = b.id.0.to_u64().unwrap();
                let block_decoded = Block::from_value(b.block.clone()).unwrap_or_else(|e| {
                    panic!(
                        "Unable to decode block at index:{} value:{:?} : {}",
                        block_id, b.block, e
                    )
                });
                (block_id, block_decoded)
            })
            .collect()
    };

    let env = &new_state_machine();
    let ledger_id = install_ledger(env);

    let txs = get_raw_blocks(env, ledger_id, vec![(0, 10)]);
    assert_eq!(txs.log_length, 0_u128);
    assert_eq!(txs.archived_blocks.len(), 0);
    assert_eq!(get_txs(&txs), vec![]);

    let depositor_id = install_depositor(env, ledger_id);
    let user1 = Account::from(Principal::from_slice(&[1]));
    let user2 = Account::from(Principal::from_slice(&[2]));
    let user3 = Account::from(Principal::from_slice(&[3]));

    // add the first mint block
    deposit(env, depositor_id, user1, 5_000_000_000, None);

    let txs = get_raw_blocks(env, ledger_id, vec![(0, 10)]);
    assert_eq!(txs.log_length, 1_u128);
    assert_eq!(txs.archived_blocks.len(), 0);
    let mut block0 = block(
        Mint {
            to: user1,
            amount: 5_000_000_000,
        },
        None,
        None,
        None,
    );
    let actual_txs = get_txs(&txs);
    let expected_txs = vec![(0, block0.clone())];
    assert_blocks_eq_except_ts(&actual_txs, &expected_txs);
    // Replace the dummy timestamp in the crafted block with the real one,
    // i.e., the timestamp the ledger wrote in the real block. This is required
    // so that we can use the hash of the block as the parent hash.
    block0.timestamp = actual_txs[0].1.timestamp;
    validate_certificate(env, ledger_id, 0, block0.hash().unwrap());

    // add a second mint block
    deposit(env, depositor_id, user2, 3_000_000_000, None);

    let txs = get_raw_blocks(env, ledger_id, vec![(0, 10)]);
    assert_eq!(txs.log_length, 2_u128);
    assert_eq!(txs.archived_blocks.len(), 0);
    let mut block1 = block(
        Mint {
            to: user2,
            amount: 3_000_000_000,
        },
        None,
        None,
        Some(block0.hash().unwrap()),
    );
    let actual_txs = get_txs(&txs);
    let expected_txs = vec![(0, block0.clone()), (1, block1.clone())];
    assert_blocks_eq_except_ts(&actual_txs, &expected_txs);
    // Replace the dummy timestamp in the crafted block with the real one,
    // i.e., the timestamp the ledger wrote in the real block. This is required
    // so that we can use the hash of the block as the parent hash.
    block1.timestamp = actual_txs[1].1.timestamp;
    validate_certificate(env, ledger_id, 1, block1.hash().unwrap());

    // check retrieving a subset of the transactions
    let txs = get_raw_blocks(env, ledger_id, vec![(0, 1)]);
    assert_eq!(txs.log_length, 2_u128);
    assert_eq!(txs.archived_blocks.len(), 0);
    let actual_txs = get_txs(&txs);
    let expected_txs = vec![(0, block0.clone())];
    assert_blocks_eq_except_ts(&actual_txs, &expected_txs);

    // add a burn block
    withdraw(
        env,
        ledger_id,
        user2,
        WithdrawArgs {
            from_subaccount: None,
            to: depositor_id,
            created_at_time: None,
            amount: Nat::from(2_000_000_000_u128),
        },
    )
    .expect("Withdraw failed");

    let txs = get_raw_blocks(env, ledger_id, vec![(0, 10)]);
    assert_eq!(txs.log_length, 3_u128);
    assert_eq!(txs.archived_blocks.len(), 0);
    let withdraw_memo = encode_withdraw_memo(&depositor_id);
    let mut block2 = block(
        Burn {
            from: user2,
            amount: 2_000_000_000,
        },
        None,
        Some(withdraw_memo),
        Some(block1.hash().unwrap()),
    );
    let actual_txs = get_txs(&txs);
    let expected_txs = vec![
        (0, block0.clone()),
        (1, block1.clone()),
        (2, block2.clone()),
    ];
    assert_blocks_eq_except_ts(&actual_txs, &expected_txs);
    // Replace the dummy timestamp in the crafted block with the real one,
    // i.e., the timestamp the ledger wrote in the real block. This is required
    // so that we can use the hash of the block as the parent hash.
    block2.timestamp = actual_txs[2].1.timestamp;
    validate_certificate(env, ledger_id, 2, block2.hash().unwrap());

    // add a couple of blocks
    transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(1_000_000_000_u128),
        },
    )
    .expect("Transfer failed");
    approve(
        env,
        ledger_id,
        /*from:*/ user1,
        /*spender:*/ user2,
        /*amount:*/ 1_000_000_000 + FEE,
        /*expected_allowance:*/ Some(0),
        /*expires_at:*/ None,
    )
    .expect("Approve failed");
    transfer_from(
        env,
        ledger_id,
        /*from:*/ user1,
        /*to:*/ user3,
        /*spender:*/ user2,
        /*amount:*/ 1_000_000_000,
    )
    .expect("Transfer from failed");

    let txs = get_raw_blocks(env, ledger_id, vec![(0, 10)]);
    assert_eq!(txs.log_length, 6_u128);
    assert_eq!(txs.archived_blocks.len(), 0);
    let actual_txs = get_txs(&txs);
    let block3 = block(
        Transfer {
            from: user1,
            to: user2,
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
            from: user1,
            spender: user2,
            amount: 1_000_000_000 + FEE,
            expected_allowance: Some(0),
            expires_at: None,
            fee: Some(FEE),
        },
        None,
        None,
        Some(actual_txs[3].1.hash().unwrap()),
    );
    let mut block5 = block(
        Transfer {
            from: user1,
            to: user3,
            spender: Some(user2),
            amount: 1_000_000_000,
            fee: Some(FEE),
        },
        None,
        None,
        Some(actual_txs[4].1.hash().unwrap()),
    );
    let expected_txs = vec![
        (0, block0.clone()),
        (1, block1.clone()),
        (2, block2.clone()),
        (3, block3.clone()),
        (4, block4.clone()),
        (5, block5.clone()),
    ];
    assert_blocks_eq_except_ts(&actual_txs, &expected_txs);
    // Replace the dummy timestamp in the crafted block with the real one,
    // i.e., the timestamp the ledger wrote in the real block. This is required
    // so that we can use the hash of the block as the parent hash.
    block5.timestamp = actual_txs[5].1.timestamp;
    validate_certificate(env, ledger_id, 5, block5.hash().unwrap());
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

    let env = new_state_machine();
    let max_blocks_per_request = 2;
    let ledger_id = install_ledger_with_conf(
        &env,
        LedgerConfig {
            max_blocks_per_request,
            index_id: None,
        },
    );
    let depositor_id = install_depositor(&env, ledger_id);

    let user = Account::from(Principal::from_slice(&[10]));
    let _ = deposit(&env, depositor_id, user, 1_000_000_000, None);
    let _ = deposit(&env, depositor_id, user, 2_000_000_000, None);
    let _ = deposit(&env, depositor_id, user, 3_000_000_000, None);
    let _ = deposit(&env, depositor_id, user, 4_000_000_000, None);
    let _ = deposit(&env, depositor_id, user, 5_000_000_000, None);

    let res = get_raw_blocks(&env, ledger_id, vec![(0, u64::MAX)]);
    assert_eq!(max_blocks_per_request, res.blocks.len() as u64);

    let res = get_raw_blocks(&env, ledger_id, vec![(3, u64::MAX)]);
    assert_eq!(max_blocks_per_request, res.blocks.len() as u64);

    let res = get_raw_blocks(&env, ledger_id, vec![(0, u64::MAX), (2, u64::MAX)]);
    assert_eq!(max_blocks_per_request, res.blocks.len() as u64);
}

#[test]
fn test_set_max_blocks_per_request_in_upgrade() {
    let env = new_state_machine();
    let ledger_id = install_ledger_with_conf(&env, LedgerConfig::default());
    let depositor_id = install_depositor(&env, ledger_id);

    let user = Account::from(Principal::from_slice(&[10]));
    let _ = deposit(&env, depositor_id, user, 1_000_000_000, None);
    let _ = deposit(&env, depositor_id, user, 2_000_000_000, None);
    let _ = deposit(&env, depositor_id, user, 3_000_000_000, None);
    let _ = deposit(&env, depositor_id, user, 4_000_000_000, None);
    let _ = deposit(&env, depositor_id, user, 5_000_000_000, None);

    let res = get_raw_blocks(&env, ledger_id, vec![(0, u64::MAX)]);
    assert_eq!(5, res.blocks.len() as u64);

    let max_blocks_per_request = 2;
    let arg = Encode!(&Some(LedgerArgs::Upgrade(Some(UpgradeArgs {
        max_blocks_per_request: Some(max_blocks_per_request),
        change_index_id: None,
    }))))
    .unwrap();
    env.upgrade_canister(ledger_id, get_wasm("cycles-ledger"), arg, None)
        .unwrap();

    let res = get_raw_blocks(&env, ledger_id, vec![(0, u64::MAX)]);
    assert_eq!(max_blocks_per_request, res.blocks.len() as u64);

    let res = get_raw_blocks(&env, ledger_id, vec![(3, u64::MAX)]);
    assert_eq!(max_blocks_per_request, res.blocks.len() as u64);

    let res = get_raw_blocks(&env, ledger_id, vec![(0, u64::MAX), (2, u64::MAX)]);
    assert_eq!(max_blocks_per_request, res.blocks.len() as u64);
}

#[test]
fn test_set_index_id_in_init() {
    let env = new_state_machine();
    let index_id = Principal::from_slice(&[111]);
    let config = LedgerConfig {
        index_id: Some(index_id),
        ..Default::default()
    };
    let ledger_id = install_ledger_with_conf(&env, config);
    let metadata = get_metadata(&env, ledger_id);
    assert_eq!(
        metadata
            .iter()
            .find_map(|(k, v)| if k == "dfn:index_id" { Some(v) } else { None }),
        Some(&index_id.as_slice().into()),
    );
}

#[test]
fn test_change_index_id() {
    let env = new_state_machine();
    let ledger_id = install_ledger_with_conf(&env, LedgerConfig::default());
    let metadata = get_metadata(&env, ledger_id);

    // by default there is no index_id set
    assert!(metadata.iter().all(|(k, _)| k != "dfn:index_id"));

    // set the index_id
    let index_id = Principal::from_slice(&[111]);
    let arg = Encode!(&Some(LedgerArgs::Upgrade(Some(UpgradeArgs {
        max_blocks_per_request: None,
        change_index_id: Some(ChangeIndexId::SetTo(index_id)),
    }))))
    .unwrap();
    env.upgrade_canister(ledger_id, get_wasm("cycles-ledger"), arg, None)
        .unwrap();
    let metadata = get_metadata(&env, ledger_id);
    assert_eq!(
        metadata
            .iter()
            .find_map(|(k, v)| if k == "dfn:index_id" { Some(v) } else { None }),
        Some(&index_id.as_slice().into()),
    );

    // unset the index_id
    let arg = Encode!(&Some(LedgerArgs::Upgrade(Some(UpgradeArgs {
        max_blocks_per_request: None,
        change_index_id: Some(ChangeIndexId::Unset),
    }))))
    .unwrap();
    env.upgrade_canister(ledger_id, get_wasm("cycles-ledger"), arg, None)
        .unwrap();
    let metadata = get_metadata(&env, ledger_id);
    assert!(metadata.iter().all(|(k, _)| k != "dfn:index_id"));
}

#[tokio::test]
async fn test_icrc1_test_suite() {
    let env = new_state_machine();
    let ledger_id = install_ledger(&env);
    let depositor_id = install_depositor(&env, ledger_id);
    let user = Account {
        owner: Principal::from_slice(&[10]),
        subaccount: Some([0; 32]),
    };

    // make the first deposit to the user and check the result
    let deposit_res = deposit(&env, depositor_id, user, 1_000_000_000_000_000, None);
    assert_eq!(deposit_res.block_index, Nat::from(0_u128));
    assert_eq!(deposit_res.balance, 1_000_000_000_000_000_u128);
    assert_eq!(1_000_000_000_000_000, balance_of(&env, ledger_id, user));

    #[allow(clippy::arc_with_non_send_sync)]
    let ledger_env =
        icrc1_test_env_state_machine::SMLedger::new(Arc::new(env), ledger_id, user.owner);
    let tests = icrc1_test_suite::test_suite(ledger_env).await;
    if !icrc1_test_suite::execute_tests(tests).await {
        panic!("The ICRC-1 test suite failed");
    }
}

#[test]
fn test_upgrade_preserves_state() {
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::TestRunner;

    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let depositor_cycles = env.cycle_balance(depositor_id);
    let mut state_machine_caller = CyclesLedgerInStateMachine {
        env,
        ledger_id,
        depositor_id,
    };

    let mut expected_state = CyclesLedgerInMemory::new(depositor_cycles);

    // generate a list of calls for the cycles ledger
    let now =
        (u64::MAX as u128).min(env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos()) as u64;
    let calls = gen::arb_cycles_ledger_call_state(depositor_id, depositor_cycles, 10, now)
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
        state_machine_caller
            .execute(&call)
            .expect("Unable to perform call on StateMachine");

        // check that the state is consistent with `expected_state`
        check_ledger_state(env, ledger_id, &expected_state);
    }

    let expected_blocks = get_raw_blocks(env, ledger_id, vec![(0, u64::MAX)]);

    // upgrade the ledger
    let arg = Encode!(&None::<LedgerArgs>).unwrap();
    env.upgrade_canister(ledger_id, get_wasm("cycles-ledger"), arg, None)
        .unwrap();

    // check that the state is still consistent with `expected_state`
    // after the upgrade
    check_ledger_state(env, ledger_id, &expected_state);

    // check that the blocks are all there after the upgrade
    let after_upgrade_blocks = get_raw_blocks(env, ledger_id, vec![(0, u64::MAX)]);
    assert_eq!(expected_blocks, after_upgrade_blocks);
}

#[track_caller]
fn check_ledger_state(
    env: &StateMachine,
    ledger_id: Principal,
    expected_state: &CyclesLedgerInMemory,
) {
    assert_eq!(expected_state.total_supply, total_supply(env, ledger_id));

    for (account, balance) in &expected_state.balances {
        assert_eq!(
            balance,
            &balance_of(env, ledger_id, *account),
            "balance_of({})",
            account
        );
    }

    for ((from, spender), allowance) in &expected_state.allowances {
        let actual_allowance = get_allowance(env, ledger_id, *from, *spender).allowance;
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
    let user = Account {
        owner: Principal::from_slice(&[10]),
        subaccount: Some([0; 32]),
    };
    let mut expected_balance = 1_000_000_000_000_000_u128;

    // make the first deposit to the user and check the result
    let deposit_res = deposit(&env, depositor_id, user, expected_balance, None);
    assert_eq!(deposit_res.block_index, Nat::from(0_u128));
    assert_eq!(deposit_res.balance, expected_balance);
    assert_eq!(expected_balance, balance_of(&env, ledger_id, user));

    // successful create
    let canister = create_canister(
        &env,
        ledger_id,
        user,
        CreateCanisterArgs {
            from_subaccount: user.subaccount,
            created_at_time: None,
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
        },
    )
    .unwrap()
    .canister_id;
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    let status = canister_status(&env, canister, user.owner);
    assert_eq!(expected_balance, balance_of(&env, ledger_id, user));
    // no canister creation fee on system subnet (where the StateMachine is by default)
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    assert_eq!(vec![user.owner], status.settings.controllers);

    let canister_settings = CanisterSettings {
        controllers: Some(vec![user.owner, Principal::anonymous()]),
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
        user,
        CreateCanisterArgs {
            from_subaccount: user.subaccount,
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
    let status = canister_status(&env, canister_id, user.owner);
    assert_eq!(expected_balance, balance_of(&env, ledger_id, user));
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
        user,
        CreateCanisterArgs {
            from_subaccount: user.subaccount,
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
    let status = canister_status(&env, canister_id, user.owner);
    assert_eq!(expected_balance, balance_of(&env, ledger_id, user));
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    assert_eq!(status.settings.controllers, vec![user.owner]);

    // reject before `await`
    if let CreateCanisterError::InsufficientFunds { balance } = create_canister(
        &env,
        ledger_id,
        user,
        CreateCanisterArgs {
            from_subaccount: user.subaccount,
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
        user,
        CreateCanisterArgs {
            from_subaccount: user.subaccount,
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
        assert_eq!(expected_balance, balance_of(&env, ledger_id, user));
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
        user,
        CreateCanisterArgs {
            from_subaccount: user.subaccount,
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
        assert_eq!(expected_balance, balance_of(&env, ledger_id, user));
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
        user,
        CreateCanisterArgs {
            from_subaccount: user.subaccount,
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
        assert_eq!(expected_balance, balance_of(&env, ledger_id, user));
    } else {
        panic!("wrong error")
    };

    // duplicate creation request returns the same canister twice
    let arg = CreateCanisterArgs {
        from_subaccount: user.subaccount,
        created_at_time: Some(env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64),
        amount: CREATE_CANISTER_CYCLES.into(),
        creation_args: None,
    };
    let canister = create_canister(&env, ledger_id, user, arg.clone())
        .unwrap()
        .canister_id;
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    let status = canister_status(&env, canister, user.owner);
    assert_eq!(expected_balance, balance_of(&env, ledger_id, user));
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    assert_eq!(vec![user.owner], status.settings.controllers);
    let duplicate = create_canister(&env, ledger_id, user, arg).unwrap_err();
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
    let user = Account {
        owner: Principal::from_slice(&[10]),
        subaccount: Some([0; 32]),
    };
    let mut expected_balance = 1_500_000_000_000_u128;

    // make the first deposit to the user and check the result
    let deposit_res = deposit(&env, depositor_id, user, expected_balance, None);
    assert_eq!(deposit_res.block_index, Nat::from(0u128));
    assert_eq!(deposit_res.balance, expected_balance);
    assert_eq!(expected_balance, balance_of(&env, ledger_id, user));

    let now = env
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // successful create
    let canister = create_canister(
        &env,
        ledger_id,
        user,
        CreateCanisterArgs {
            from_subaccount: user.subaccount,
            created_at_time: Some(now),
            amount: CREATE_CANISTER_CYCLES.into(),
            creation_args: None,
        },
    )
    .unwrap()
    .canister_id;
    expected_balance -= CREATE_CANISTER_CYCLES + FEE;
    let status = canister_status(&env, canister, user.owner);
    assert_eq!(expected_balance, balance_of(&env, ledger_id, user));
    // no canister creation fee on system subnet (where the StateMachine is by default)
    assert_eq!(CREATE_CANISTER_CYCLES, status.cycles);
    assert_eq!(vec![user.owner], status.settings.controllers);

    assert_eq!(
        CreateCanisterError::Duplicate {
            duplicate_of: Nat::from(1u128),
            canister_id: Some(canister)
        },
        create_canister(
            &env,
            ledger_id,
            user,
            CreateCanisterArgs {
                from_subaccount: user.subaccount,
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
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };

    // Attempt deposit with memo exceeding `MAX_MEMO_LENGTH`. This call should panic.
    let large_memo = [0; MAX_MEMO_LENGTH as usize + 1];

    let arg = Encode!(&depositor::endpoints::DepositArg {
        cycles: 10 * FEE,
        to: user,
        memo: Some(Memo(ByteBuf::from(large_memo))),
    })
    .unwrap();

    let _res = env
        .update_call(depositor_id, user.owner, "deposit", arg)
        .unwrap();
}

#[test]
#[should_panic(expected = "memo length exceeds the maximum")]
fn test_icrc1_transfer_invalid_memo() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user1 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };
    let user2: Account = Account {
        owner: Principal::from_slice(&[2]),
        subaccount: None,
    };
    let deposit_amount = 1_000_000_000;
    deposit(env, depositor_id, user1, deposit_amount, None);

    // Attempt icrc1_transfer with memo exceeding `MAX_MEMO_LENGTH`. This call should panic.
    let large_memo = [0; MAX_MEMO_LENGTH as usize + 1];

    let transfer_amount = Nat::from(100_000_u128);
    let _res = transfer(
        env,
        ledger_id,
        user1.owner,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: None,
            memo: Some(Memo(ByteBuf::from(large_memo))),
            amount: transfer_amount.clone(),
        },
    );
}

#[test]
#[should_panic(expected = "memo length exceeds the maximum")]
fn test_approve_invalid_memo() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user1 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };
    let user2: Account = Account {
        owner: Principal::from_slice(&[2]),
        subaccount: None,
    };
    let deposit_amount = 1_000_000_000;
    deposit(env, depositor_id, user1, deposit_amount, None);

    // Attempt approve with memo exceeding `MAX_MEMO_LENGTH`. This call should panic.
    let large_memo = [0; MAX_MEMO_LENGTH as usize + 1];

    let args = ApproveArgs {
        from_subaccount: None,
        spender: user2,
        amount: (1_000_000_000 + FEE).into(),
        expected_allowance: Some(Nat::from(0u128)),
        expires_at: None,
        fee: Some(Nat::from(FEE)),
        memo: Some(Memo(ByteBuf::from(large_memo))),
        created_at_time: None,
    };
    let res = if let WasmResult::Reply(res) = env
        .update_call(
            ledger_id,
            user1.owner,
            "icrc2_approve",
            Encode!(&args).unwrap(),
        )
        .unwrap()
    {
        Decode!(&res, Result<Nat, ApproveError>).unwrap()
    } else {
        panic!("icrc2_approve rejected")
    };

    res.unwrap();
}

#[test]
#[should_panic(expected = "memo length exceeds the maximum")]
fn test_icrc2_transfer_from_invalid_memo() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user1 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };
    let user2: Account = Account {
        owner: Principal::from_slice(&[2]),
        subaccount: None,
    };
    let deposit_amount = 10_000_000_000;
    deposit(env, depositor_id, user1, deposit_amount, None);

    // Attempt transfer_from with memo exceeding `MAX_MEMO_LENGTH`. This call should panic.
    let large_memo = [0; MAX_MEMO_LENGTH as usize + 1];

    let transfer_amount = Nat::from(100_000_u128);

    approve(
        env,
        ledger_id,
        /*from:*/ user1,
        /*spender:*/ user2,
        /*amount:*/ 1_000_000_000 + FEE,
        /*expected_allowance:*/ Some(0),
        /*expires_at:*/ None,
    )
    .expect("Approve failed");

    let args = TransferFromArgs {
        spender_subaccount: None,
        from: user1,
        to: user2,
        amount: transfer_amount,
        fee: Some(Nat::from(FEE)),
        memo: Some(Memo(ByteBuf::from(large_memo))),
        created_at_time: None,
    };

    let res = if let WasmResult::Reply(res) = env
        .update_call(
            ledger_id,
            user2.owner,
            "icrc2_transfer_from",
            Encode!(&args).unwrap(),
        )
        .unwrap()
    {
        Decode!(&res, Result<Nat, TransferFromError>).unwrap()
    } else {
        panic!("icrc2_transfer_from rejected")
    };

    res.unwrap();
}
