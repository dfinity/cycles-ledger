use core::panic;
use std::collections::BTreeMap;

use candid::{CandidType, Decode, Encode, Nat, Principal};
use cycles_ledger::{
    endpoints::{
        self, CmcCreateCanisterError, CreateCanisterArgs, CreateCanisterFromArgs,
        CreateCanisterSuccess, DataCertificate, DepositResult, GetBlocksArg, GetBlocksArgs,
        GetBlocksResult, WithdrawArgs, WithdrawFromArgs,
    },
    storage::{Block, CMC_PRINCIPAL},
};
use depositor::endpoints::DepositArg;
use ic_management_canister_types::CanisterStatusResult;
use icrc_ledger_types::icrc106::errors::Icrc106Error;
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
use pocket_ic::PocketIc;
use serde::Deserialize;

// Panics if the canister is unreachable or it has rejected the query.
pub fn query_or_panic<I, O>(
    env: &PocketIc,
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
        Ok(res) => Decode!(&res, O).unwrap(),
    }
}

// Panics if the canister is unreachable or it has rejected the update.
pub fn update_or_panic<I, O>(
    env: &PocketIc,
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
        Ok(res) => Decode!(&res, O).unwrap(),
    }
}

pub fn deposit(
    env: &PocketIc,
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

pub fn icrc1_balance_of(env: &PocketIc, ledger_id: Principal, account: Account) -> u128 {
    let res: Nat = query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "icrc1_balance_of",
        account,
    );
    res.0.to_u128().unwrap()
}

pub fn icrc1_fee(env: &PocketIc, ledger_id: Principal) -> u128 {
    let res: Nat = query_or_panic(env, ledger_id, Principal::anonymous(), "icrc1_fee", ());
    res.0.to_u128().unwrap()
}

pub fn icrc1_total_supply(env: &PocketIc, ledger_id: Principal) -> u128 {
    let res: Nat = query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "icrc1_total_supply",
        (),
    );
    res.0.to_u128().unwrap()
}

pub fn get_block(env: &PocketIc, ledger_id: Principal, block_index: Nat) -> Block {
    let value = icrc3_get_blocks(env, ledger_id, vec![(block_index, Nat::from(1u64))])
        .blocks
        .remove(0)
        .block;
    Block::from_value(value).unwrap()
}

pub fn withdraw(
    env: &PocketIc,
    ledger_id: Principal,
    caller: Principal,
    args: WithdrawArgs,
) -> Result<Nat, endpoints::WithdrawError> {
    update_or_panic(env, ledger_id, caller, "withdraw", args)
}

pub fn withdraw_from(
    env: &PocketIc,
    ledger_id: Principal,
    caller: Principal,
    args: WithdrawFromArgs,
) -> Result<Nat, endpoints::WithdrawFromError> {
    update_or_panic(env, ledger_id, caller, "withdraw_from", args)
}

pub fn create_canister(
    env: &PocketIc,
    ledger_id: Principal,
    caller: Principal,
    args: CreateCanisterArgs,
) -> Result<CreateCanisterSuccess, endpoints::CreateCanisterError> {
    update_or_panic(env, ledger_id, caller, "create_canister", args)
}

pub fn create_canister_from(
    env: &PocketIc,
    ledger_id: Principal,
    caller: Principal,
    args: CreateCanisterFromArgs,
) -> Result<CreateCanisterSuccess, endpoints::CreateCanisterFromError> {
    update_or_panic(env, ledger_id, caller, "create_canister_from", args)
}

pub fn canister_status(
    env: &PocketIc,
    canister_id: Principal,
    caller: Principal,
) -> CanisterStatusResult {
    env.canister_status(canister_id, Some(caller))
        .expect("canister_status should succeed")
}

pub fn fail_next_create_canister_with(env: &PocketIc, error: CmcCreateCanisterError) {
    let arg = Encode!(&error).unwrap();
    env.update_call(
        CMC_PRINCIPAL,
        Principal::anonymous(),
        "fail_next_create_canister_with",
        arg,
    )
    .expect("fail_next_create_canister_with should succeed");
}

pub fn icrc2_allowance(
    env: &PocketIc,
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
    env: &PocketIc,
    ledger_id: Principal,
    caller: Principal,
    args: ApproveArgs,
) -> Result<Nat, ApproveError> {
    update_or_panic(env, ledger_id, caller, "icrc2_approve", args)
}

pub fn icrc103_get_allowances(
    env: &PocketIc,
    ledger_id: Principal,
    caller: Principal,
    args: GetAllowancesArgs,
) -> Result<Allowances, GetAllowancesError> {
    query_or_panic(env, ledger_id, caller, "icrc103_get_allowances", args)
}

pub fn icrc106_get_index_principal(
    env: &PocketIc,
    ledger_id: Principal,
) -> Result<Principal, Icrc106Error> {
    query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "icrc106_get_index_principal",
        (),
    )
}

pub fn icrc1_transfer(
    env: &PocketIc,
    ledger_id: Principal,
    from_owner: Principal,
    args: TransferArgs,
) -> Result<Nat, TransferError> {
    update_or_panic(env, ledger_id, from_owner, "icrc1_transfer", args)
}

pub fn icrc2_transfer_from(
    env: &PocketIc,
    ledger_id: Principal,
    caller: Principal,
    args: TransferFromArgs,
) -> Result<Nat, TransferFromError> {
    update_or_panic(env, ledger_id, caller, "icrc2_transfer_from", args)
}

pub fn icrc1_metadata(env: &PocketIc, ledger_id: Principal) -> Vec<(String, MetadataValue)> {
    query_or_panic(env, ledger_id, Principal::anonymous(), "icrc1_metadata", ())
}

pub fn icrc3_get_blocks<N: Into<Nat>>(
    env: &PocketIc,
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

pub fn transaction_hashes(env: &PocketIc, ledger_id: Principal) -> BTreeMap<[u8; 32], u64> {
    query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "get_transaction_hashes",
        (),
    )
}

pub fn transaction_timestamps(env: &PocketIc, ledger_id: Principal) -> BTreeMap<(u64, u64), ()> {
    query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "get_transaction_timestamps",
        (),
    )
}

pub fn get_tip_certificate(env: &PocketIc, ledger_id: Principal) -> DataCertificate {
    let res: Option<DataCertificate> = query_or_panic(
        env,
        ledger_id,
        Principal::anonymous(),
        "icrc3_get_tip_certificate",
        (),
    );
    res.expect("icrc3_get_tip_certificate should return a non-null result for query calls")
}
