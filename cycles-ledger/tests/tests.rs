use candid::{Encode, Nat};
use client::deposit;
use cycles_ledger::{config::FEE, Account, endpoints::SendArg};
use depositer::endpoints::InitArg as DeposterInitArg;
use escargot::CargoBuild;
use ic_cdk::api::call::RejectionCode;
use ic_state_machine_tests::{CanisterId, Cycles, PrincipalId, StateMachine};

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
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env);
    let depositer_id = install_depositer(env, ledger_id);
    let user = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
        subaccount: None,
    };
    let send_receiver = env.create_canister(None);

    // make the first deposit to the user and check the result
    let deposit_res = deposit(env, depositer_id, user, 1_000_000_000);
    assert_eq!(deposit_res.txid, Nat::from(0));
    assert_eq!(deposit_res.balance, Nat::from(1_000_000_000 - FEE));
    let depositer_balance = env.cycle_balance(send_receiver);
    println!("depositer balance: {}", depositer_balance);

    // send cycles to send_receiver
    let send_amount = 500000000_u128;
    let _send_idx = send(env, ledger_id, user, SendArg{
        from_subaccount: None,
        to: send_receiver.into(),
        fee: None,
        created_at_time: None,
        memo: None,
        amount: Nat::from(send_amount),
    }).unwrap();
    assert_eq!(depositer_balance + send_amount, env.cycle_balance(send_receiver));

    // check that the user has the right balance
    assert_eq!(
        balance_of(env, ledger_id, user),
        Nat::from(1_000_000_000 - FEE - send_amount - FEE)
    );

}

#[test]
fn test_send_fails() {
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env);
    let depositer_id = install_depositer(env, ledger_id);
    let user = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
        subaccount: None,
    };
    let send_receiver = env.create_canister(None);
    env.stop_canister(send_receiver).unwrap();
    env.delete_canister(send_receiver).unwrap();

    // make the first deposit to the user and check the result
    let deposit_res = deposit(env, depositer_id, user, 1_000_000_000);
    assert_eq!(deposit_res.txid, Nat::from(0));
    assert_eq!(deposit_res.balance, Nat::from(1_000_000_000 - FEE));

    // send cycles to non-existent send_receiver
    let send_result = send(env, ledger_id, user, SendArg{
        from_subaccount: None,
        to: send_receiver.into(),
        fee: None,
        created_at_time: None,
        memo: None,
        amount: Nat::from(500_000_000_u128),
    }).unwrap_err();

    assert!(matches!(send_result, cycles_ledger::endpoints::SendError::FailedToSend { rejection_code: RejectionCode::DestinationInvalid, .. }));

    // check that the user has the right balance
    assert_eq!(
        balance_of(env, ledger_id, user),
        Nat::from(1_000_000_000 - FEE - FEE)
    );
}

#[test]
fn test_send_input_rejected() {
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env);
    let depositer_id = install_depositer(env, ledger_id);
    let user = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
        subaccount: None,
    };

    // make the first deposit to the user and check the result
    let deposit_res = deposit(env, depositer_id, user, 1_000_000_000);
    assert_eq!(deposit_res.txid, Nat::from(0));
    assert_eq!(deposit_res.balance, Nat::from(1_000_000_000 - FEE));

    // send more than available
    let send_amount = 999_000_000_000_u128;
    let send_result = send(env, ledger_id, user, SendArg{
        from_subaccount: None,
        to: depositer_id.into(),
        fee: None,
        created_at_time: None,
        memo: None,
        amount: Nat::from(send_amount),
    }).unwrap_err();
    println!("send more than available result: {:?}", &send_result);
    assert!(matches!(send_result, cycles_ledger::endpoints::SendError::InsufficientFunds{ .. }));

    // send from empty subaccount
    let send_result = send(env, ledger_id, user, SendArg{
        from_subaccount: Some([5; 32]),
        to: depositer_id.into(),
        fee: None,
        created_at_time: None,
        memo: None,
        amount: Nat::from(100_000_000_u128),
    }).unwrap_err();
    println!("send from empty subaccount result: {:?}", &send_result);
    assert!(matches!(send_result, cycles_ledger::endpoints::SendError::InsufficientFunds{ .. }));

    // bad fee
    let send_result = send(env, ledger_id, user, SendArg{
        from_subaccount: None,
        to: depositer_id.into(),
        fee: Some(Nat::from(4)),
        created_at_time: None,
        memo: None,
        amount: Nat::from(100_000_000_u128),
    }).unwrap_err();
    println!("bad fee result: {:?}", &send_result);
    assert!(matches!(send_result, cycles_ledger::endpoints::SendError::BadFee{ .. }));
}
