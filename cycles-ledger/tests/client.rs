use candid::{Decode, Encode, Nat, Principal};
use cycles_ledger::endpoints::{self, DepositResult, SendArg};
use depositor::endpoints::DepositArg;
use ic_test_state_machine_client::{StateMachine, WasmResult};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{TransferArg, TransferError},
};
use num_traits::ToPrimitive;

pub fn deposit(
    env: &StateMachine,
    depositor_id: Principal,
    to: Account,
    cycles: u128,
) -> DepositResult {
    let arg = Encode!(&DepositArg {
        cycles,
        to,
        memo: None
    })
    .unwrap();
    if let WasmResult::Reply(res) = env
        .update_call(depositor_id, to.owner, "deposit", arg)
        .unwrap()
    {
        Decode!(&res, DepositResult).unwrap()
    } else {
        panic!("deposit rejected")
    }
}

pub fn balance_of(env: &StateMachine, ledger_id: Principal, account: Account) -> u128 {
    let arg = Encode!(&account).unwrap();
    if let WasmResult::Reply(res) = env
        .query_call(ledger_id, Principal::anonymous(), "icrc1_balance_of", arg)
        .unwrap()
    {
        Decode!(&res, Nat).unwrap().0.to_u128().unwrap()
    } else {
        panic!("balance_of rejected")
    }
}

pub fn send(
    env: &StateMachine,
    ledger_id: Principal,
    from: Account,
    args: SendArg,
) -> Result<Nat, endpoints::SendError> {
    let arg = Encode!(&args).unwrap();
    if let WasmResult::Reply(res) = env.update_call(ledger_id, from.owner, "send", arg).unwrap() {
        Decode!(&res, Result<candid::Nat, cycles_ledger::endpoints::SendError>).unwrap()
    } else {
        panic!("send rejected")
    }
}

pub fn transfer(
    env: &StateMachine,
    ledger_id: Principal,
    from: Account,
    args: TransferArg,
) -> Result<Nat, TransferError> {
    let arg = Encode!(&args).unwrap();
    if let WasmResult::Reply(res) = env
        .update_call(ledger_id, from.owner, "icrc1_transfer", arg)
        .unwrap()
    {
        Decode!(&res, Result<candid::Nat, TransferError>).unwrap()
    } else {
        panic!("transfer rejected")
    }
}

pub fn fee(env: &StateMachine, ledger_id: Principal) -> Nat {
    let arg = Encode!(&()).unwrap();
    if let WasmResult::Reply(res) = env
        .query_call(ledger_id, Principal::anonymous(), "icrc1_fee", arg)
        .unwrap()
    {
        Decode!(&res, Nat).unwrap()
    } else {
        panic!("fee call rejected")
    }
}
