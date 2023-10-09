use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use assert_matches::assert_matches;
use candid::{Encode, Nat, Principal};
use client::{deposit, get_raw_transactions, transaction_hashes, transfer, transfer_from};
use cycles_ledger::{
    config::{self, Config as LedgerConfig, FEE},
    endpoints::{
        DataCertificate, GetTransactionsResult, LedgerArgs, SendArgs, SendError, UpgradeArgs,
    },
    memo::encode_send_memo,
    storage::{
        Block, Hash,
        Operation::{self, Approve, Burn, Mint, Transfer},
        Transaction,
    },
};
use depositor::endpoints::InitArg as DepositorInitArg;
use escargot::CargoBuild;
use futures::FutureExt;
use ic_cbor::CertificateToCbor;
use ic_cdk::api::call::RejectionCode;
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{
    hash_tree::{HashTreeNode, SubtreeLookupResult},
    Certificate, HashTree, LookupResult,
};
use ic_test_state_machine_client::{ErrorCode, StateMachine};
use icrc_ledger_types::{
    icrc1::{
        account::Account,
        transfer::TransferArg as TransferArgs,
        transfer::{Memo, TransferError},
    },
    icrc2::approve::ApproveArgs,
};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde_bytes::ByteBuf;

use crate::client::{
    approve, balance_of, fee, get_allowance, get_tip_certificate, send, total_supply,
    transaction_timestamps,
};

mod client;

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
        let suggested_ic_commit = "a17247bd86c7aa4e87742bf74d108614580f216d";

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

#[test]
fn test_deposit_flow() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user = Account {
        owner: Principal::from_slice(&[0]),
        subaccount: None,
    };

    // Check that the total supply is 0
    assert_eq!(total_supply(env, ledger_id), 0u128);

    // Check that the user doesn't have any tokens before the first deposit.
    assert_eq!(balance_of(env, ledger_id, user), 0u128);

    // Make the first deposit to the user and check the result.
    let deposit_res = deposit(env, depositor_id, user, 1_000_000_000);
    assert_eq!(deposit_res.txid, Nat::from(0));
    assert_eq!(deposit_res.balance, Nat::from(1_000_000_000));

    // Check that the right amount of tokens have been minted
    assert_eq!(total_supply(env, ledger_id), 1_000_000_000);

    // Check that the user has the right balance.
    assert_eq!(balance_of(env, ledger_id, user), 1_000_000_000);

    // Make another deposit to the user and check the result.
    let deposit_res = deposit(env, depositor_id, user, 500_000_000);
    assert_eq!(deposit_res.txid, Nat::from(1));
    assert_eq!(deposit_res.balance, Nat::from(1_500_000_000));

    // Check that the right amount of tokens have been minted
    assert_eq!(total_supply(env, ledger_id), 1_500_000_000);

    // Check that the user has the right balance after both deposits.
    assert_eq!(balance_of(env, ledger_id, user), 1_500_000_000);
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
    let _deposit_result = deposit(env, depositor_id, user, config::FEE - 1);
}

#[test]
fn test_send_flow() {
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
    let send_receiver = env.create_canister(None);

    // make deposits to the user and check the result
    let deposit_res = deposit(env, depositor_id, user_main_account, 1_000_000_000);
    assert_eq!(deposit_res.txid, 0);
    assert_eq!(deposit_res.balance, 1_000_000_000);
    deposit(env, depositor_id, user_subaccount_1, 1_000_000_000);
    deposit(env, depositor_id, user_subaccount_2, 1_000_000_000);
    deposit(env, depositor_id, user_subaccount_3, 1_000_000_000);
    deposit(env, depositor_id, user_subaccount_4, 1_000_000_000);
    let mut expected_total_supply = 5_000_000_000;
    assert_eq!(total_supply(env, ledger_id), expected_total_supply);

    // send cycles from main account
    let send_receiver_balance = env.cycle_balance(send_receiver);
    let send_amount = 500_000_000_u128;
    let _send_idx = send(
        env,
        ledger_id,
        user_main_account,
        SendArgs {
            from_subaccount: None,
            to: send_receiver,
            created_at_time: None,
            amount: Nat::from(send_amount),
        },
    )
    .unwrap();
    assert_eq!(
        send_receiver_balance + send_amount,
        env.cycle_balance(send_receiver)
    );
    assert_eq!(
        balance_of(env, ledger_id, user_main_account),
        1_000_000_000 - send_amount - FEE
    );
    expected_total_supply -= send_amount + FEE;
    assert_eq!(total_supply(env, ledger_id), expected_total_supply);

    // send cycles from subaccount
    let send_receiver_balance = env.cycle_balance(send_receiver);
    let send_amount = 100_000_000_u128;
    let _send_idx = send(
        env,
        ledger_id,
        user_subaccount_1,
        SendArgs {
            from_subaccount: Some(*user_subaccount_1.effective_subaccount()),
            to: send_receiver,
            created_at_time: None,
            amount: Nat::from(send_amount),
        },
    )
    .unwrap();
    assert_eq!(
        send_receiver_balance + send_amount,
        env.cycle_balance(send_receiver)
    );
    assert_eq!(
        balance_of(env, ledger_id, user_subaccount_1),
        1_000_000_000 - send_amount - FEE
    );
    expected_total_supply -= send_amount + FEE;
    assert_eq!(total_supply(env, ledger_id), expected_total_supply);

    // send cycles from subaccount with created_at_time set
    let now = env
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let send_receiver_balance = env.cycle_balance(send_receiver);
    let send_amount = 300_000_000_u128;
    let _send_idx = send(
        env,
        ledger_id,
        user_subaccount_3,
        SendArgs {
            from_subaccount: Some(*user_subaccount_3.effective_subaccount()),
            to: send_receiver,
            created_at_time: Some(now),
            amount: Nat::from(send_amount),
        },
    )
    .unwrap();
    assert_eq!(
        send_receiver_balance + send_amount,
        env.cycle_balance(send_receiver)
    );
    assert_eq!(
        balance_of(env, ledger_id, user_subaccount_3),
        1_000_000_000 - send_amount - FEE
    );
    expected_total_supply -= send_amount + FEE;
    assert_eq!(total_supply(env, ledger_id), expected_total_supply);
}

#[test]
fn test_send_fails() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };

    // make the first deposit to the user and check the result
    let deposit_res = deposit(env, depositor_id, user, 1_000_000_000_000);
    assert_eq!(deposit_res.txid, Nat::from(0));
    assert_eq!(deposit_res.balance, 1_000_000_000_000_u128);

    // send more than available
    let balance_before_attempt = balance_of(env, ledger_id, user);
    let send_result = send(
        env,
        ledger_id,
        user,
        SendArgs {
            from_subaccount: None,
            to: depositor_id,
            created_at_time: None,
            amount: Nat::from(u128::MAX),
        },
    )
    .unwrap_err();
    assert!(matches!(
        send_result,
        SendError::InsufficientFunds { balance } if balance == 1_000_000_000_000_u128
    ));
    assert_eq!(balance_before_attempt, balance_of(env, ledger_id, user));
    let mut expected_total_supply = 1_000_000_000_000;
    assert_eq!(total_supply(env, ledger_id), expected_total_supply,);

    // send from empty subaccount
    let send_result = send(
        env,
        ledger_id,
        user,
        SendArgs {
            from_subaccount: Some([5; 32]),
            to: depositor_id,
            created_at_time: None,
            amount: Nat::from(100_000_000_u128),
        },
    )
    .unwrap_err();
    assert!(matches!(
        send_result,
        SendError::InsufficientFunds { balance } if balance == 0
    ));
    assert_eq!(total_supply(env, ledger_id), expected_total_supply,);

    // send cycles to user instead of canister
    let balance_before_attempt = balance_of(env, ledger_id, user);
    let self_authenticating_principal = candid::Principal::from_text(
        "luwgt-ouvkc-k5rx5-xcqkq-jx5hm-r2rj2-ymqjc-pjvhb-kij4p-n4vms-gqe",
    )
    .unwrap();
    let send_result = send(
        env,
        ledger_id,
        user,
        SendArgs {
            from_subaccount: None,
            to: self_authenticating_principal,
            created_at_time: None,
            amount: Nat::from(500_000_000_u128),
        },
    )
    .unwrap_err();
    assert!(matches!(
        send_result,
        SendError::InvalidReceiver { receiver } if receiver == self_authenticating_principal
    ));
    assert_eq!(balance_before_attempt, balance_of(env, ledger_id, user));
    assert_eq!(total_supply(env, ledger_id), expected_total_supply,);

    // send cycles to deleted canister
    let balance_before_attempt = balance_of(env, ledger_id, user);
    let deleted_canister = env.create_canister(None);
    env.stop_canister(deleted_canister, None).unwrap();
    env.delete_canister(deleted_canister, None).unwrap();
    let send_result = send(
        env,
        ledger_id,
        user,
        SendArgs {
            from_subaccount: None,
            to: deleted_canister,
            created_at_time: None,
            amount: Nat::from(500_000_000_u128),
        },
    )
    .unwrap_err();
    assert!(matches!(
        send_result,
        SendError::FailedToSend {
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
    deposit(env, depositor_id, user_2, FEE + 1);
    send(
        env,
        ledger_id,
        user_2,
        SendArgs {
            from_subaccount: None,
            to: depositor_id,
            created_at_time: None,
            amount: Nat::from(u128::MAX),
        },
    )
    .unwrap_err();
    assert_eq!(FEE + 1, balance_of(env, ledger_id, user_2));
    send(
        env,
        ledger_id,
        user_2,
        SendArgs {
            from_subaccount: None,
            to: depositor_id,
            created_at_time: None,
            amount: Nat::from(u128::MAX),
        },
    )
    .unwrap_err();
    assert_eq!(FEE + 1, balance_of(env, ledger_id, user_2));

    // test send deduplication
    deposit(env, depositor_id, user_2, FEE * 3);
    let created_at_time = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let args = SendArgs {
        from_subaccount: None,
        to: depositor_id,
        created_at_time: Some(created_at_time),
        amount: Nat::from(FEE),
    };
    let duplicate_of = send(env, ledger_id, user_2, args.clone()).unwrap();
    // the same send should fail because created_at_time is set and the args are the same
    assert_eq!(
        send(env, ledger_id, user_2, args),
        Err(SendError::Duplicate { duplicate_of })
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
        deposit(env, depositor_id, from, 1_000_000_000).balance,
        1_000_000_000
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
    assert_eq!(block_index, 1);
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
        deposit(env, depositor_id, from, 1_000_000_000).balance,
        1_000_000_000
    );

    let args = ApproveArgs {
        from_subaccount: None,
        spender: from,
        amount: Nat::from(100),
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
        deposit(env, depositor_id, from, 1_000_000_000).balance,
        1_000_000_000
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
        deposit(env, depositor_id, from, 1_000_000_000).balance,
        1_000_000_000
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
    assert_eq!(block_index, 1);
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
    assert_eq!(block_index, 2);
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
    assert_eq!(allowance.allowance, Nat::from(0));
    assert_eq!(allowance.expires_at, None);
    let allowance = get_allowance(env, ledger_id, from, spender2);
    assert_eq!(allowance.allowance, Nat::from(200_000_000_u128));
    assert_eq!(allowance.expires_at, Some(expiration_3h));
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
    deposit(env, depositor_id, user1, deposit_amount);
    let fee = fee(env, ledger_id);
    let mut expected_total_supply = deposit_amount;

    let transfer_amount = Nat::from(100_000);
    transfer(
        env,
        ledger_id,
        user1,
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
            user2,
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
            user1,
            TransferArgs {
                from_subaccount: None,
                to: user1,
                fee: Some(Nat::from(0)),
                created_at_time: None,
                memo: None,
                amount: transfer_amount.clone(),
            },
        )
        .unwrap_err()
    );
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
    deposit(env, depositor_id, user1, deposit_amount);
    let transfer_amount = Nat::from(100_000);

    // If created_at_time is not set, the same transaction should be able to be sent multiple times
    transfer(
        env,
        ledger_id,
        user1,
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
        user1,
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
            user1,
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
        user1,
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
            user1,
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
        user1,
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
        user1,
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

#[test]
fn test_pruning_transactions() {
    let env = &new_state_machine();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user1 = Account {
        owner: Principal::from_slice(&[1]),
        subaccount: None,
    };
    let transfer_amount = Nat::from(100_000);

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
    deposit(env, depositor_id, user1, deposit_amount);

    // A deposit does not have a `created_at_time` argument and is therefore not recorded
    let tx_hashes = transaction_hashes(env, ledger_id);
    assert!(tx_hashes.is_empty());

    // Create a transfer where `created_at_time` is not set
    transfer(
        env,
        ledger_id,
        user1,
        TransferArgs {
            from_subaccount: None,
            to: Principal::anonymous().into(),
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
        user1,
        TransferArgs {
            from_subaccount: None,
            to: Principal::anonymous().into(),
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
        user1,
        TransferArgs {
            from_subaccount: None,
            to: Principal::anonymous().into(),
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
        user1,
        TransferArgs {
            from_subaccount: None,
            to: Principal::anonymous().into(),
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

    deposit(env, depositor_id, user1, 2_000_000_000);
    deposit(env, depositor_id, user2, 3_000_000_000);
    let fee = fee(env, ledger_id);
    transfer(
        env,
        ledger_id,
        user1,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(1_000_000_000),
        },
    )
    .unwrap();
    send(
        env,
        ledger_id,
        user2,
        SendArgs {
            from_subaccount: None,
            to: depositor_id,
            created_at_time: None,
            amount: Nat::from(1_000_000_000),
        },
    )
    .unwrap();

    // total_supply should be 5m - 1m sent back to the depositor - twice the fee for transfer and send
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

    let hash_tree: HashTree = serde_cbor::de::from_slice(hash_tree.as_slice())
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
fn test_icrc3_get_transactions() {
    // Utility to extract all IDs and the corresponding transactions from the given [GetTransactionsResult].
    let get_txs = |res: &GetTransactionsResult| -> Vec<(u64, Block)> {
        res.transactions
            .iter()
            .map(|tx| {
                let tx_id = tx.id.0.to_u64().unwrap();
                let tx_decoded = Block::from_value(tx.transaction.clone()).unwrap_or_else(|e| {
                    panic!(
                        "Unable to decode block at index:{} value:{:?} : {}",
                        tx_id, tx.transaction, e
                    )
                });
                (tx_id, tx_decoded)
            })
            .collect()
    };

    let env = &new_state_machine();
    let ledger_id = install_ledger(env);

    let txs = get_raw_transactions(env, ledger_id, vec![(0, 10)]);
    assert_eq!(txs.log_length, 0);
    assert_eq!(txs.archived_transactions.len(), 0);
    assert_eq!(get_txs(&txs), vec![]);

    let depositor_id = install_depositor(env, ledger_id);
    let user1 = Account::from(Principal::from_slice(&[1]));
    let user2 = Account::from(Principal::from_slice(&[2]));
    let user3 = Account::from(Principal::from_slice(&[3]));

    // add the first mint block
    deposit(env, depositor_id, user1, 5_000_000_000);

    let txs = get_raw_transactions(env, ledger_id, vec![(0, 10)]);
    assert_eq!(txs.log_length, 1);
    assert_eq!(txs.archived_transactions.len(), 0);
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
    validate_certificate(env, ledger_id, 0, block0.hash());

    // add a second mint block
    deposit(env, depositor_id, user2, 3_000_000_000);

    let txs = get_raw_transactions(env, ledger_id, vec![(0, 10)]);
    assert_eq!(txs.log_length, 2);
    assert_eq!(txs.archived_transactions.len(), 0);
    let mut block1 = block(
        Mint {
            to: user2,
            amount: 3_000_000_000,
        },
        None,
        None,
        Some(block0.hash()),
    );
    let actual_txs = get_txs(&txs);
    let expected_txs = vec![(0, block0.clone()), (1, block1.clone())];
    assert_blocks_eq_except_ts(&actual_txs, &expected_txs);
    // Replace the dummy timestamp in the crafted block with the real one,
    // i.e., the timestamp the ledger wrote in the real block. This is required
    // so that we can use the hash of the block as the parent hash.
    block1.timestamp = actual_txs[1].1.timestamp;
    validate_certificate(env, ledger_id, 1, block1.hash());

    // check retrieving a subset of the transactions
    let txs = get_raw_transactions(env, ledger_id, vec![(0, 1)]);
    assert_eq!(txs.log_length, 2);
    assert_eq!(txs.archived_transactions.len(), 0);
    let actual_txs = get_txs(&txs);
    let expected_txs = vec![(0, block0.clone())];
    assert_blocks_eq_except_ts(&actual_txs, &expected_txs);

    // add a burn block
    send(
        env,
        ledger_id,
        user2,
        SendArgs {
            from_subaccount: None,
            to: depositor_id,
            created_at_time: None,
            amount: Nat::from(2_000_000_000),
        },
    )
    .expect("Send failed");

    let txs = get_raw_transactions(env, ledger_id, vec![(0, 10)]);
    assert_eq!(txs.log_length, 3);
    assert_eq!(txs.archived_transactions.len(), 0);
    let send_memo = encode_send_memo(&depositor_id);
    let mut block2 = block(
        Burn {
            from: user2,
            amount: 2_000_000_000,
        },
        None,
        Some(send_memo),
        Some(block1.hash()),
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
    validate_certificate(env, ledger_id, 2, block2.hash());

    // add a couple of blocks
    transfer(
        env,
        ledger_id,
        user1,
        TransferArgs {
            from_subaccount: None,
            to: user2,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(1_000_000_000),
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

    let txs = get_raw_transactions(env, ledger_id, vec![(0, 10)]);
    assert_eq!(txs.log_length, 6);
    assert_eq!(txs.archived_transactions.len(), 0);
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
        Some(block2.hash()),
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
        Some(actual_txs[3].1.hash()),
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
        Some(actual_txs[4].1.hash()),
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
    validate_certificate(env, ledger_id, 5, block5.hash());
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
fn test_get_transactions_max_length() {
    // Check that the ledger doesn't return more blocks
    // than configured. We set the max number of transactions
    // per request to 2 instead of the default because
    // it's much faster to test.

    let env = new_state_machine();
    let max_transactions_per_request = 2;
    let ledger_id = install_ledger_with_conf(
        &env,
        LedgerConfig {
            max_transactions_per_request,
        },
    );
    let depositor_id = install_depositor(&env, ledger_id);

    let user = Account::from(Principal::from_slice(&[10]));
    let _ = deposit(&env, depositor_id, user, 1_000_000_000);
    let _ = deposit(&env, depositor_id, user, 2_000_000_000);
    let _ = deposit(&env, depositor_id, user, 3_000_000_000);
    let _ = deposit(&env, depositor_id, user, 4_000_000_000);
    let _ = deposit(&env, depositor_id, user, 5_000_000_000);

    let res = get_raw_transactions(&env, ledger_id, vec![(0, u64::MAX)]);
    assert_eq!(max_transactions_per_request, res.transactions.len() as u64);

    let res = get_raw_transactions(&env, ledger_id, vec![(3, u64::MAX)]);
    assert_eq!(max_transactions_per_request, res.transactions.len() as u64);

    let res = get_raw_transactions(&env, ledger_id, vec![(0, u64::MAX), (2, u64::MAX)]);
    assert_eq!(max_transactions_per_request, res.transactions.len() as u64);
}

#[test]
fn test_set_max_transactions_per_request_in_upgrade() {
    let env = new_state_machine();
    let ledger_id = install_ledger_with_conf(&env, LedgerConfig::default());
    let depositor_id = install_depositor(&env, ledger_id);

    let user = Account::from(Principal::from_slice(&[10]));
    let _ = deposit(&env, depositor_id, user, 1_000_000_000);
    let _ = deposit(&env, depositor_id, user, 2_000_000_000);
    let _ = deposit(&env, depositor_id, user, 3_000_000_000);
    let _ = deposit(&env, depositor_id, user, 4_000_000_000);
    let _ = deposit(&env, depositor_id, user, 5_000_000_000);

    let res = get_raw_transactions(&env, ledger_id, vec![(0, u64::MAX)]);
    assert_eq!(5, res.transactions.len() as u64);

    let max_transactions_per_request = 2;
    let arg = Encode!(&Some(LedgerArgs::Upgrade(UpgradeArgs {
        max_transactions_per_request: Some(max_transactions_per_request)
    })))
    .unwrap();
    env.upgrade_canister(ledger_id, get_wasm("cycles-ledger"), arg, None)
        .unwrap();

    let res = get_raw_transactions(&env, ledger_id, vec![(0, u64::MAX)]);
    assert_eq!(max_transactions_per_request, res.transactions.len() as u64);

    let res = get_raw_transactions(&env, ledger_id, vec![(3, u64::MAX)]);
    assert_eq!(max_transactions_per_request, res.transactions.len() as u64);

    let res = get_raw_transactions(&env, ledger_id, vec![(0, u64::MAX), (2, u64::MAX)]);
    assert_eq!(max_transactions_per_request, res.transactions.len() as u64);
}

#[test]
fn test_icrc1_test_suite() {
    let env = new_state_machine();
    let ledger_id = install_ledger(&env);
    let depositor_id = install_depositor(&env, ledger_id);
    let user = Account {
        owner: Principal::from_slice(&[10]),
        subaccount: Some([0; 32]),
    };

    // make the first deposit to the user and check the result
    let deposit_res = deposit(&env, depositor_id, user, 1_000_000_000_000_000);
    assert_eq!(deposit_res.txid, Nat::from(0));
    assert_eq!(deposit_res.balance, 1_000_000_000_000_000_u128);
    assert_eq!(1_000_000_000_000_000, balance_of(&env, ledger_id, user));

    let ledger_env =
        icrc1_test_env_state_machine::SMLedger::new(Arc::new(env), ledger_id, user.owner);
    let tests = icrc1_test_suite::test_suite(ledger_env)
        .now_or_never()
        .unwrap();
    if !icrc1_test_suite::execute_tests(tests)
        .now_or_never()
        .unwrap()
    {
        panic!("The ICRC-1 test suite failed");
    }
}
