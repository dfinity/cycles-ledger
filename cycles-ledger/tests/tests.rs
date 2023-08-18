use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};

use candid::{Encode, Nat, Principal};
use client::{deposit, transfer};
use cycles_ledger::{
    config::{self, FEE},
    endpoints::{SendArg, SendErrorReason},
};
use depositor::endpoints::InitArg as DepositorInitArg;
use escargot::CargoBuild;
use ic_cdk::api::call::RejectionCode;
use ic_test_state_machine_client::StateMachine;
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{Memo, TransferArg, TransferError},
};
use serde_bytes::ByteBuf;

use crate::client::{balance_of, fee, send};

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
        .run()
        .expect("Unable to run cargo build");
    std::fs::read(binary.path()).unwrap_or_else(|_| panic!("{} wasm file not found", name))
}

fn install_ledger(env: &StateMachine) -> Principal {
    let canister = env.create_canister(None);
    env.install_canister(canister, get_wasm("cycles-ledger"), vec![], None);
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

    // Check that the user doesn't have any tokens before the first deposit.
    assert_eq!(balance_of(env, ledger_id, user), 0u128);

    // Make the first deposit to the user and check the result.
    let deposit_res = deposit(env, depositor_id, user, 1_000_000_000);
    assert_eq!(deposit_res.txid, Nat::from(0));
    assert_eq!(deposit_res.balance, Nat::from(1_000_000_000));

    // Check that the user has the right balance.
    assert_eq!(balance_of(env, ledger_id, user), Nat::from(1_000_000_000));

    // Make another deposit to the user and check the result.
    let deposit_res = deposit(env, depositor_id, user, 500_000_000);
    assert_eq!(deposit_res.txid, Nat::from(1));
    assert_eq!(deposit_res.balance, Nat::from(1_500_000_000));

    // Check that the user has the right balance after both deposits.
    assert_eq!(balance_of(env, ledger_id, user), Nat::from(1_500_000_000));
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
    assert_eq!(deposit_res.txid, Nat::from(0));
    assert_eq!(deposit_res.balance, Nat::from(1_000_000_000));
    deposit(env, depositor_id, user_subaccount_1, 1_000_000_000);
    deposit(env, depositor_id, user_subaccount_2, 1_000_000_000);
    deposit(env, depositor_id, user_subaccount_3, 1_000_000_000);
    deposit(env, depositor_id, user_subaccount_4, 1_000_000_000);

    // send cycles from main account
    let send_receiver_balance = env.cycle_balance(send_receiver);
    let send_amount = 500000000_u128;
    let _send_idx = send(
        env,
        ledger_id,
        user_main_account,
        SendArg {
            from_subaccount: None,
            to: send_receiver,
            fee: None,
            created_at_time: None,
            memo: None,
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
        Nat::from(1_000_000_000 - send_amount - FEE)
    );

    // send cycles from subaccount
    let send_receiver_balance = env.cycle_balance(send_receiver);
    let send_amount = 100_000_000_u128;
    let _send_idx = send(
        env,
        ledger_id,
        user_subaccount_1,
        SendArg {
            from_subaccount: Some(*user_subaccount_1.effective_subaccount()),
            to: send_receiver,
            fee: None,
            created_at_time: None,
            memo: None,
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

    // send cycles from subaccount with the correct fee set
    let send_receiver_balance = env.cycle_balance(send_receiver);
    let send_amount = 200_000_000_u128;
    let _send_idx = send(
        env,
        ledger_id,
        user_subaccount_2,
        SendArg {
            from_subaccount: Some(*user_subaccount_2.effective_subaccount()),
            to: send_receiver,
            fee: Some(Nat::from(config::FEE)),
            created_at_time: None,
            memo: None,
            amount: Nat::from(send_amount),
        },
    )
    .unwrap();
    assert_eq!(
        send_receiver_balance + send_amount,
        env.cycle_balance(send_receiver)
    );
    assert_eq!(
        balance_of(env, ledger_id, user_subaccount_2),
        1_000_000_000 - send_amount - FEE
    );

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
        SendArg {
            from_subaccount: Some(*user_subaccount_3.effective_subaccount()),
            to: send_receiver,
            fee: None,
            created_at_time: Some(now),
            memo: None,
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

    // send cycles from subaccount with Memo set
    let send_receiver_balance = env.cycle_balance(send_receiver);
    let send_amount = 300_000_000_u128;
    let _send_idx = send(
        env,
        ledger_id,
        user_subaccount_4,
        SendArg {
            from_subaccount: Some(*user_subaccount_4.effective_subaccount()),
            to: send_receiver,
            fee: None,
            created_at_time: None,
            memo: Some(Memo(ByteBuf::from([5; 32]))),
            amount: Nat::from(send_amount),
        },
    )
    .unwrap();
    assert_eq!(
        send_receiver_balance + send_amount,
        env.cycle_balance(send_receiver)
    );
    assert_eq!(
        balance_of(env, ledger_id, user_subaccount_4),
        1_000_000_000 - send_amount - FEE
    );
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
        SendArg {
            from_subaccount: None,
            to: depositor_id,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(u128::MAX),
        },
    )
    .unwrap_err();
    assert!(matches!(
        send_result.reason,
        SendErrorReason::InsufficientFunds { balance } if balance == 1_000_000_000_000_u128
    ));
    assert_eq!(
        balance_before_attempt - FEE,
        balance_of(env, ledger_id, user)
    );

    // send from empty subaccount
    let send_result = send(
        env,
        ledger_id,
        user,
        SendArg {
            from_subaccount: Some([5; 32]),
            to: depositor_id,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(100_000_000_u128),
        },
    )
    .unwrap_err();
    assert!(matches!(
        send_result.reason,
        SendErrorReason::InsufficientFunds { balance } if balance == 0
    ));

    // bad fee
    let balance_before_attempt = balance_of(env, ledger_id, user);
    let send_result = send(
        env,
        ledger_id,
        user,
        SendArg {
            from_subaccount: None,
            to: depositor_id,
            fee: Some(FEE + Nat::from(1)),
            created_at_time: None,
            memo: None,
            amount: Nat::from(100_000_000_u128),
        },
    )
    .unwrap_err();
    assert!(matches!(
        send_result.reason,
        SendErrorReason::BadFee { expected_fee } if expected_fee == config::FEE
    ));
    assert_eq!(
        balance_before_attempt - FEE,
        balance_of(env, ledger_id, user)
    );

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
        SendArg {
            from_subaccount: None,
            to: self_authenticating_principal,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(500_000_000_u128),
        },
    )
    .unwrap_err();
    assert!(matches!(
        send_result.reason,
        SendErrorReason::InvalidReceiver { receiver } if receiver == self_authenticating_principal
    ));
    assert_eq!(
        balance_before_attempt - FEE,
        balance_of(env, ledger_id, user)
    );

    // send cycles to deleted canister
    let balance_before_attempt = balance_of(env, ledger_id, user);
    let deleted_canister = env.create_canister(None);
    env.stop_canister(deleted_canister, None).unwrap();
    env.delete_canister(deleted_canister, None).unwrap();
    let send_result = send(
        env,
        ledger_id,
        user,
        SendArg {
            from_subaccount: None,
            to: deleted_canister,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(500_000_000_u128),
        },
    )
    .unwrap_err();
    assert!(matches!(
        send_result.reason,
        SendErrorReason::FailedToSend {
            rejection_code: RejectionCode::DestinationInvalid,
            ..
        }
    ));
    assert_eq!(
        balance_before_attempt - FEE,
        balance_of(env, ledger_id, user)
    );

    // user loses all cycles if they don't have enough balance to pay the fee
    let user_2 = Account {
        owner: Principal::from_slice(&[2]),
        subaccount: None,
    };
    deposit(env, depositor_id, user_2, FEE + 1);
    send(
        env,
        ledger_id,
        user_2,
        SendArg {
            from_subaccount: None,
            to: depositor_id,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(u128::MAX),
        },
    )
    .unwrap_err();
    assert_eq!(1, balance_of(env, ledger_id, user_2));
    send(
        env,
        ledger_id,
        user_2,
        SendArg {
            from_subaccount: None,
            to: depositor_id,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(u128::MAX),
        },
    )
    .unwrap_err();
    assert_eq!(0, balance_of(env, ledger_id, user_2));
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

    let transfer_amount = Nat::from(100_000);
    transfer(
        env,
        ledger_id,
        user1,
        TransferArg {
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

    // Should not be able to send back the full amount as the user2 cannot pay the fee
    assert_eq!(
        TransferError::InsufficientFunds {
            balance: transfer_amount.clone()
        },
        transfer(
            env,
            ledger_id,
            user2,
            TransferArg {
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

    // Should not be able to set a fee that is incorrect
    assert_eq!(
        TransferError::BadFee {
            expected_fee: fee.clone()
        },
        transfer(
            env,
            ledger_id,
            user1,
            TransferArg {
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
        TransferArg {
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
        TransferArg {
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
            TransferArg {
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
        TransferArg {
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
            TransferArg {
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
        TransferArg {
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
        TransferArg {
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
