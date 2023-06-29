use candid::{Encode, Nat};
use client::deposit;
use cycles_ledger::{
    config::{self, FEE},
    endpoints::{Memo, SendArg, SendErrorReason},
    Account,
};
use depositor::endpoints::InitArg as DepositorInitArg;
use escargot::CargoBuild;
use ic_cdk::api::call::RejectionCode;
use ic_state_machine_tests::{CanisterId, Cycles, PrincipalId, StateMachine};
use serde_bytes::ByteBuf;

use crate::client::{balance_of, send};

mod client;

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

fn install_ledger(env: &StateMachine) -> CanisterId {
    env.install_canister(get_wasm("cycles-ledger"), vec![], None)
        .unwrap()
}

fn install_depositor(env: &StateMachine, ledger_id: CanisterId) -> CanisterId {
    let depositor_init_arg = Encode!(&DepositorInitArg {
        ledger_id: ledger_id.into()
    })
    .unwrap();
    env.install_canister_with_cycles(
        get_wasm("depositor"),
        depositor_init_arg,
        None,
        Cycles::new(u128::MAX),
    )
    .unwrap()
}

#[test]
fn test_deposit_flow() {
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
        subaccount: None,
    };

    // Check that the user doesn't have any tokens before the first deposit.
    assert_eq!(balance_of(env, ledger_id, user), 0u128);

    // Make the first deposit to the user and check the result.
    let deposit_res = deposit(env, depositor_id, user, 1_000_000_000);
    assert_eq!(deposit_res.txid, Nat::from(0));
    assert_eq!(deposit_res.balance, Nat::from(1_000_000_000));

    // Check that the user has the right balance.
    assert_eq!(balance_of(env, ledger_id, user), Nat::from(1_000_000_000))
}

#[test]
fn test_send_flow() {
    // TODO(SDK-1145): Add re-entrancy test

    let env = &StateMachine::new();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user_main_account = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
        subaccount: None,
    };
    let user_subaccount_1 = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
        subaccount: Some([1; 32]),
    };
    let user_subaccount_2 = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
        subaccount: Some([2; 32]),
    };
    let user_subaccount_3 = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
        subaccount: Some([3; 32]),
    };
    let user_subaccount_4 = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
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
            to: send_receiver.into(),
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
            to: send_receiver.into(),
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
            to: send_receiver.into(),
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
    let send_receiver_balance = env.cycle_balance(send_receiver);
    let send_amount = 300_000_000_u128;
    let _send_idx = send(
        env,
        ledger_id,
        user_subaccount_3,
        SendArg {
            from_subaccount: Some(*user_subaccount_3.effective_subaccount()),
            to: send_receiver.into(),
            fee: None,
            created_at_time: Some(100_u64),
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
            to: send_receiver.into(),
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
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
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
            to: depositor_id.into(),
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
            to: depositor_id.into(),
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
            to: depositor_id.into(),
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
    env.stop_canister(deleted_canister).unwrap();
    env.delete_canister(deleted_canister).unwrap();
    let send_result = send(
        env,
        ledger_id,
        user,
        SendArg {
            from_subaccount: None,
            to: deleted_canister.into(),
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
        owner: PrincipalId::new_user_test_id(2).into(),
        subaccount: None,
    };
    deposit(env, depositor_id, user_2, FEE + 1);
    send(
        env,
        ledger_id,
        user_2,
        SendArg {
            from_subaccount: None,
            to: depositor_id.into(),
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
            to: depositor_id.into(),
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(u128::MAX),
        },
    )
    .unwrap_err();
    assert_eq!(0, balance_of(env, ledger_id, user_2));
}
