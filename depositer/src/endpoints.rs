use candid::{CandidType, Principal};
use cycles_ledger::{endpoints::Memo, Account};
use serde::Deserialize;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InitArg {
    pub ledger_id: Principal,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DepositArg {
    pub cycles: u128,
    pub to: Account,
    pub memo: Option<Memo>,
}
