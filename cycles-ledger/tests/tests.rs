use candid::{Encode, Nat};
use client::deposit;
use cycles_ledger::{config::FEE, Account};
use depositer::endpoints::InitArg as DeposterInitArg;
use escargot::CargoBuild;
use ic_state_machine_tests::{CanisterId, Cycles, PrincipalId, StateMachine};

use crate::client::balance_of;

mod client;

fn cycles_ledger_wasm() -> Vec<u8> {
    println!(
        "{}",
        std::path::Path::new("..").canonicalize().unwrap().display()
    );
    let binary = CargoBuild::new()
        .manifest_path("../Cargo.toml")
        .target("wasm32-unknown-unknown")
        .bin("cycles-ledger")
        .arg("--release")
        .run()
        .expect("Unable to run cargo build");
    std::fs::read(&binary.path()).expect("cycles-ledger wasm file not found")
}

fn depositer_wasm() -> Vec<u8> {
    let binary = CargoBuild::new()
        .manifest_path("../Cargo.toml")
        .target("wasm32-unknown-unknown")
        .bin("depositer")
        .arg("--release")
        .run()
        .expect("Unable to run cargo build");
    std::fs::read(&binary.path()).expect("depositer wasm file not found")
}

fn install_ledger(env: &StateMachine) -> CanisterId {
    env.install_canister(cycles_ledger_wasm(), vec![], None)
        .unwrap()
}

fn install_depositer(env: &StateMachine, ledger_id: CanisterId) -> CanisterId {
    let depositer_init_arg = Encode!(&DeposterInitArg {
        ledger_id: ledger_id.into()
    })
    .unwrap();
    env.install_canister_with_cycles(
        depositer_wasm(),
        depositer_init_arg,
        None,
        Cycles::new(u128::MAX),
    )
    .unwrap()
}

#[test]
fn test_deposit_flow() {
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env);
    let depositer_id = install_depositer(env, ledger_id);
    let user = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
        subaccount: None,
    };

    // check that the user doesn't have any tokens before the first deposit
    assert_eq!(balance_of(env, ledger_id, user), 0u128);

    // make the first deposit to the user and check the result
    let deposit_res = deposit(env, depositer_id, user, 1_000_000_000);
    assert_eq!(deposit_res.txid, Nat::from(0));
    assert_eq!(deposit_res.balance, Nat::from(1_000_000_000 - FEE));

    // check that the user has the right balance
    assert_eq!(
        balance_of(env, ledger_id, user),
        Nat::from(1_000_000_000 - FEE)
    )
}
