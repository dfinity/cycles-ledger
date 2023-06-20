use candid::{Decode, Encode, Nat};
use cycles_ledger::{endpoints::{DepositResult, SendArg, self}, Account};
use depositer::endpoints::DepositArg;
use ic_state_machine_tests::{CanisterId, StateMachine};
use num_traits::ToPrimitive;

pub fn deposit(
    env: &StateMachine,
    depositer_id: CanisterId,
    to: Account,
    cycles: u128,
) -> DepositResult {
    let arg = Encode!(&DepositArg {
        cycles,
        to,
        memo: None
    })
    .unwrap();
    let res = env
        .execute_ingress_as(to.owner.into(), depositer_id, "deposit", arg)
        .unwrap();
    Decode!(&res.bytes(), DepositResult).unwrap()
}

pub fn balance_of(env: &StateMachine, ledger_id: CanisterId, account: Account) -> u128 {
    let arg = Encode!(&account).unwrap();
    let res = env
        .query_as(account.owner.into(), ledger_id, "icrc1_balance_of", arg)
        .unwrap();
    Decode!(&res.bytes(), Nat).unwrap().0.to_u128().unwrap()
}

pub fn send(env: &StateMachine, ledger_id: CanisterId, from: Account, args: SendArg) -> Result<Nat, endpoints::SendError> {
    let arg = Encode!(&args).unwrap();
    let res = env.execute_ingress_as(ic_state_machine_tests::PrincipalId(from.owner), ledger_id, "send", arg).unwrap();
    Decode!(&res.bytes(), Result<candid::Nat, cycles_ledger::endpoints::SendError>).unwrap()
}
