use candid::{CandidType, Deserialize, Nat, Principal};
use ic_cdk::api::call::RejectionCode;
use icrc_ledger_types::icrc1::{
    account::{Account, Subaccount},
    transfer::{BlockIndex, Memo},
};

pub type NumCycles = Nat;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DepositArg {
    pub to: Account,
    pub memo: Option<Memo>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DepositResult {
    pub txid: Nat,
    pub balance: Nat,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SupportedStandard {
    pub name: String,
    pub url: String,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SendArg {
    #[serde(default)]
    pub from_subaccount: Option<Subaccount>,
    pub to: Principal,
    #[serde(default)]
    pub fee: Option<NumCycles>,
    #[serde(default)]
    pub created_at_time: Option<u64>,
    #[serde(default)]
    pub memo: Option<Memo>,
    pub amount: NumCycles,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SendError {
    pub fee_block: Nat,
    pub reason: SendErrorReason,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum SendErrorReason {
    BadFee {
        expected_fee: NumCycles,
    },
    InsufficientFunds {
        balance: NumCycles,
    },
    TooOld,
    CreatedInFuture {
        ledger_time: u64,
    },
    TemporarilyUnavailable,
    Duplicate {
        duplicate_of: BlockIndex,
    },
    FailedToSend {
        rejection_code: RejectionCode,
        rejection_reason: String,
    },
    GenericError {
        error_code: Nat,
        message: String,
    },
    InvalidReceiver {
        receiver: Principal,
    },
}
