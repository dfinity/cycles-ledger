use core::panic;
use std::collections::BTreeMap;

use candid::{Decode, Encode, Nat, Principal};
use cycles_ledger::{
    config::FEE,
    endpoints::{
        self, DataCertificate, DepositResult, GetTransactionsArg, GetTransactionsArgs,
        GetTransactionsResult, SendArgs,
    },
};
use depositor::endpoints::DepositArg;
use ic_test_state_machine_client::{StateMachine, WasmResult};
use icrc_ledger_types::{
    icrc1::account::Account,
    icrc1::transfer::TransferArg as TransferArgs,
    icrc1::transfer::TransferError,
    icrc2::{
        allowance::{Allowance, AllowanceArgs},
        approve::{ApproveArgs, ApproveError},
        transfer_from::{TransferFromArgs, TransferFromError},
    },
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
        panic!("icrc1_balance_of rejected")
    }
}

pub fn total_supply(env: &StateMachine, ledger_id: Principal) -> u128 {
    let arg = Encode!(&()).unwrap();
    if let WasmResult::Reply(res) = env
        .query_call(ledger_id, Principal::anonymous(), "icrc1_total_supply", arg)
        .unwrap()
    {
        Decode!(&res, Nat).unwrap().0.to_u128().unwrap()
    } else {
        panic!("icrc1_total_supply rejected")
    }
}

pub fn send(
    env: &StateMachine,
    ledger_id: Principal,
    from: Account,
    args: SendArgs,
) -> Result<Nat, endpoints::SendError> {
    let arg = Encode!(&args).unwrap();
    if let WasmResult::Reply(res) = env.update_call(ledger_id, from.owner, "send", arg).unwrap() {
        Decode!(&res, Result<candid::Nat, cycles_ledger::endpoints::SendError>).unwrap()
    } else {
        panic!("send rejected")
    }
}

pub fn get_allowance(
    env: &StateMachine,
    ledger_id: Principal,
    from: Account,
    spender: Account,
) -> Allowance {
    let args = AllowanceArgs {
        account: from,
        spender,
    };
    if let WasmResult::Reply(res) = env
        .query_call(
            ledger_id,
            Principal::anonymous(),
            "icrc2_allowance",
            Encode!(&args).unwrap(),
        )
        .unwrap()
    {
        Decode!(&res, Allowance).unwrap()
    } else {
        panic!("allowance rejected")
    }
}

pub fn approve(
    env: &StateMachine,
    ledger_id: Principal,
    from: Account,
    spender: Account,
    amount: u128,
    expected_allowance: Option<u128>,
    expires_at: Option<u64>,
) -> Result<Nat, ApproveError> {
    let args = ApproveArgs {
        from_subaccount: from.subaccount,
        spender,
        amount: amount.into(),
        expected_allowance: expected_allowance.map(Nat::from),
        expires_at,
        fee: Some(Nat::from(FEE)),
        memo: None,
        created_at_time: None,
    };
    if let WasmResult::Reply(res) = env
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
    }
}

pub fn transfer(
    env: &StateMachine,
    ledger_id: Principal,
    from: Account,
    args: TransferArgs,
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

pub fn transfer_from(
    env: &StateMachine,
    ledger_id: Principal,
    from: Account,
    to: Account,
    spender: Account,
    amount: u128,
) -> Result<Nat, TransferFromError> {
    let args = TransferFromArgs {
        spender_subaccount: spender.subaccount,
        from,
        to,
        amount: amount.into(),
        fee: Some(Nat::from(FEE)),
        memo: None,
        created_at_time: None,
    };
    if let WasmResult::Reply(res) = env
        .update_call(
            ledger_id,
            spender.owner,
            "icrc2_transfer_from",
            Encode!(&args).unwrap(),
        )
        .unwrap()
    {
        Decode!(&res, Result<Nat, TransferFromError>).unwrap()
    } else {
        panic!("icrc2_transfer_from rejected")
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

pub fn get_raw_transactions(
    env: &StateMachine,
    ledger_id: Principal,
    start_lengths: Vec<(u64, u64)>,
) -> GetTransactionsResult {
    let get_transactions_args: GetTransactionsArgs = start_lengths
        .iter()
        .map(|(start, length)| GetTransactionsArg {
            start: Nat::from(*start),
            length: Nat::from(*length),
        })
        .collect();
    let arg = Encode!(&get_transactions_args).unwrap();
    if let WasmResult::Reply(res) = env
        .query_call(
            ledger_id,
            Principal::anonymous(),
            "icrc3_get_transactions",
            arg,
        )
        .unwrap()
    {
        Decode!(&res, GetTransactionsResult).unwrap()
    } else {
        panic!("fee call rejected")
    }
}

pub fn transaction_hashes(env: &StateMachine, ledger_id: Principal) -> BTreeMap<[u8; 32], u64> {
    let arg = Encode!(&()).unwrap();
    if let WasmResult::Reply(res) = env
        .query_call(
            ledger_id,
            Principal::anonymous(),
            "get_transaction_hashes",
            arg,
        )
        .unwrap()
    {
        Decode!(&res, BTreeMap<[u8; 32],u64>).unwrap()
    } else {
        panic!("fee call rejected")
    }
}

pub fn transaction_timestamps(
    env: &StateMachine,
    ledger_id: Principal,
) -> BTreeMap<(u64, u64), ()> {
    let arg = Encode!(&()).unwrap();
    if let WasmResult::Reply(res) = env
        .query_call(
            ledger_id,
            Principal::anonymous(),
            "get_transaction_timestamps",
            arg,
        )
        .unwrap()
    {
        Decode!(&res, BTreeMap<(u64, u64),()>).unwrap()
    } else {
        panic!("fee call rejected")
    }
}

pub fn get_data_certificate(env: &StateMachine, ledger_id: Principal) -> DataCertificate {
    let arg = Encode!(&()).unwrap();
    if let WasmResult::Reply(res) = env
        .query_call(
            ledger_id,
            Principal::anonymous(),
            "icrc3_get_data_certificate",
            arg,
        )
        .unwrap()
    {
        Decode!(&res, DataCertificate).unwrap()
    } else {
        panic!("icrc3_get_data_certificate call rejected")
    }
}
