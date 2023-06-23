use candid::{Encode, Nat};
use client::deposit;
use cycles_ledger::{config, Account};
use depositor::endpoints::InitArg as DepositorInitArg;
use escargot::CargoBuild;
use ic_state_machine_tests::{CanisterId, Cycles, PrincipalId, StateMachine};

use crate::client::balance_of;

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
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env);
    let depositor_id = install_depositor(env, ledger_id);
    let user = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
        subaccount: None,
    };

    // Attempt to deposit fewer than [config::FEE] cycles. This call should panic.
    let _deposit_result = deposit(env, depositor_id, user, config::FEE - 1);
}
