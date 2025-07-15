use core::panic;
use std::collections::BTreeMap;

use candid::{CandidType, Decode, Encode, Nat, Principal};
use cycles_ledger::{
    endpoints::{
        self, AdminMintArg, AdminMintResult, CmcCreateCanisterError, CreateCanisterArgs,
        CreateCanisterFromArgs, CreateCanisterSuccess, DataCertificate, DepositResult,
        GetBlocksArg, GetBlocksArgs, GetBlocksResult, WithdrawArgs, WithdrawFromArgs,
    },
    storage::{Block, CMC_PRINCIPAL},
};
use depositor::endpoints::DepositArg;
use ic_cdk::api::management_canister::{
    main::CanisterStatusResponse, provisional::CanisterIdRecord,
};
use ic_test_state_machine_client::{StateMachine, WasmResult};
use icrc_ledger_types::{
    icrc::generic_metadata_value::MetadataValue,
    icrc1::{
        account::Account,
        transfer::{Memo, TransferArg as TransferArgs, TransferError},
    },
    icrc103::get_allowances::{Allowances, GetAllowancesArgs, GetAllowancesError},
    icrc2::{
        allowance::{Allowance, AllowanceArgs},
        approve::{ApproveArgs, ApproveError},
        transfer_from::{TransferFromArgs, TransferFromError},
    },
};
use num_traits::ToPrimitive;
use serde::Deserialize;

// Panics if the canister is unreachable or it has rejected the query.
pub fn query_or_panic<I, O>(
    env: &StateMachine,
    canister_id: Principal,
    caller: Principal,
    method: &str,
    arg: I,
) -> O
where
    I: CandidType,
    O: CandidType + for<'a> Deserialize<'a>,
{
    let arg = Encode!(&arg).unwrap();
    match env.query_call(canister_id, caller, method, arg) {
        Err(err) => {
            panic!("{canister_id}.{method} query failed with error {err} (caller: {caller})");
        }
        Ok(WasmResult::Reject(err)) => {
            panic!("{canister_id}.{method} query rejected with error {err} (caller: {caller})");
        }
        Ok(WasmResult::Reply(res)) => Decode!(&res, O).unwrap(),
    }
}

// Panics if the canister is unreachable or it has rejected the update.
pub fn update_or_panic<I, O>(
    env: &StateMachine,
    canister_id: Principal,
    caller: Principal,
    method: &str,
    arg: I,
) -> O
where
    I: CandidType,
    O: CandidType + for<'a> Deserialize<'a>,
{
    let arg = Encode!(&arg).unwrap();
    match env.update_call(canister_id, caller, method, arg) {
        Err(err) => {
            panic!("{canister_id}.{method} failed with error {err} (caller: {caller})");
        }
        Ok(WasmResult::Reject(err)) => {
            panic!("{canister_id}.{method} rejected with error {err} (caller: {caller})");
        }
        Ok(WasmResult::Reply(res)) => Decode!(&res, O).unwrap(),
    }
}

pub fn deposit(
    env: &StateMachine,
    depositor_id: Principal,
    to: Account,
    cycles: u128,
    memo: Option<Memo>,
) -> DepositResult {
    update_or_panic(
        env,
        depositor_id,
        to.owner,
        "deposit",
        DepositArg { cycles, to, memo },
    )
}

pub fn admin_mint(
    env: &StateMachine,
    cycles_ledger: Principal,
    caller: Principal,
    to: Account,
    cycles: u128,
    memo: Option<Memo>,
) -> AdminMintResult {
    update_or_panic(
        env,
        cycles_ledger,
        caller,
        "admin_mint",
        AdminMintArg {
            amount: Nat::from(cycles),
            to,
            memo,
        },
    )
}

pub fn icrc1_balance_of(env: &StateMachine, ledger_id: Principal, account: Account) -> u128 {
    let res: Nat = query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "icrc1_balance_of",
        account,
    );
    res.0.to_u128().unwrap()
}

pub fn icrc1_fee(env: &StateMachine, ledger_id: Principal) -> u128 {
    let res: Nat = query_or_panic(env, ledger_id, Principal::anonymous(), "icrc1_fee", ());
    res.0.to_u128().unwrap()
}

pub fn icrc1_total_supply(env: &StateMachine, ledger_id: Principal) -> u128 {
    let res: Nat = query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "icrc1_total_supply",
        (),
    );
    res.0.to_u128().unwrap()
}

pub fn get_block(env: &StateMachine, ledger_id: Principal, block_index: Nat) -> Block {
    let value = icrc3_get_blocks(env, ledger_id, vec![(block_index, Nat::from(1u64))])
        .blocks
        .remove(0)
        .block;
    Block::from_value(value).unwrap()
}

pub fn withdraw(
    env: &StateMachine,
    ledger_id: Principal,
    caller: Principal,
    args: WithdrawArgs,
) -> Result<Nat, endpoints::WithdrawError> {
    update_or_panic(env, ledger_id, caller, "withdraw", args)
}

pub fn withdraw_from(
    env: &StateMachine,
    ledger_id: Principal,
    caller: Principal,
    args: WithdrawFromArgs,
) -> Result<Nat, endpoints::WithdrawFromError> {
    update_or_panic(env, ledger_id, caller, "withdraw_from", args)
}

pub fn create_canister(
    env: &StateMachine,
    ledger_id: Principal,
    caller: Principal,
    args: CreateCanisterArgs,
) -> Result<CreateCanisterSuccess, endpoints::CreateCanisterError> {
    update_or_panic(env, ledger_id, caller, "create_canister", args)
}

pub fn create_canister_from(
    env: &StateMachine,
    ledger_id: Principal,
    caller: Principal,
    args: CreateCanisterFromArgs,
) -> Result<CreateCanisterSuccess, endpoints::CreateCanisterFromError> {
    update_or_panic(env, ledger_id, caller, "create_canister_from", args)
}

pub fn canister_status(
    env: &StateMachine,
    canister_id: Principal,
    caller: Principal,
) -> CanisterStatusResponse {
    update_or_panic(
        env,
        Principal::management_canister(),
        caller,
        "canister_status",
        CanisterIdRecord { canister_id },
    )
}

pub fn fail_next_create_canister_with(env: &StateMachine, error: CmcCreateCanisterError) {
    let arg = Encode!(&error).unwrap();
    if !matches!(
        env.update_call(
            CMC_PRINCIPAL,
            Principal::anonymous(),
            "fail_next_create_canister_with",
            arg,
        )
        .unwrap(),
        WasmResult::Reply(_)
    ) {
        panic!("canister_status rejected")
    }
}

pub fn icrc2_allowance(
    env: &StateMachine,
    ledger_id: Principal,
    from: Account,
    spender: Account,
) -> Allowance {
    query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "icrc2_allowance",
        AllowanceArgs {
            account: from,
            spender,
        },
    )
}

pub fn icrc2_approve(
    env: &StateMachine,
    ledger_id: Principal,
    caller: Principal,
    args: ApproveArgs,
) -> Result<Nat, ApproveError> {
    update_or_panic(env, ledger_id, caller, "icrc2_approve", args)
}

pub fn icrc103_get_allowances(
    env: &StateMachine,
    ledger_id: Principal,
    caller: Principal,
    args: GetAllowancesArgs,
) -> Result<Allowances, GetAllowancesError> {
    query_or_panic(env, ledger_id, caller, "icrc103_get_allowances", args)
}

pub fn icrc1_transfer(
    env: &StateMachine,
    ledger_id: Principal,
    from_owner: Principal,
    args: TransferArgs,
) -> Result<Nat, TransferError> {
    update_or_panic(env, ledger_id, from_owner, "icrc1_transfer", args)
}

pub fn icrc2_transfer_from(
    env: &StateMachine,
    ledger_id: Principal,
    caller: Principal,
    args: TransferFromArgs,
) -> Result<Nat, TransferFromError> {
    update_or_panic(env, ledger_id, caller, "icrc2_transfer_from", args)
}

pub fn icrc1_metadata(env: &StateMachine, ledger_id: Principal) -> Vec<(String, MetadataValue)> {
    query_or_panic(env, ledger_id, Principal::anonymous(), "icrc1_metadata", ())
}

pub fn icrc3_get_blocks<N: Into<Nat>>(
    env: &StateMachine,
    ledger_id: Principal,
    start_lengths: Vec<(N, N)>,
) -> GetBlocksResult {
    let args: GetBlocksArgs = start_lengths
        .into_iter()
        .map(|(start, length)| GetBlocksArg {
            start: start.into(),
            length: length.into(),
        })
        .collect();
    query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "icrc3_get_blocks",
        args,
    )
}

pub fn transaction_hashes(env: &StateMachine, ledger_id: Principal) -> BTreeMap<[u8; 32], u64> {
    query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "get_transaction_hashes",
        (),
    )
}

pub fn transaction_timestamps(
    env: &StateMachine,
    ledger_id: Principal,
) -> BTreeMap<(u64, u64), ()> {
    query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "get_transaction_timestamps",
        (),
    )
}

pub fn get_tip_certificate(env: &StateMachine, ledger_id: Principal) -> DataCertificate {
    let res: Option<DataCertificate> = query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "icrc3_get_tip_certificate",
        (),
    );
    res.expect("icrc3_get_tip_certificate should return a non-null result for query calls")
}
