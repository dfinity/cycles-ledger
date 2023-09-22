use std::marker::PhantomData;

use candid::{CandidType, Deserialize, Nat, Principal};
use ic_cdk::api::call::RejectionCode;
use icrc_ledger_types::{
    icrc::generic_value::Value,
    icrc1::{
        account::{Account, Subaccount},
        transfer::{BlockIndex, Memo},
    },
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
pub struct SendArgs {
    #[serde(default)]
    pub from_subaccount: Option<Subaccount>,
    pub to: Principal,
    #[serde(default)]
    pub created_at_time: Option<u64>,
    pub amount: NumCycles,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum SendError {
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
        fee_block: Option<Nat>,
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

pub enum DeduplicationError {
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: BlockIndex },
}

impl From<DeduplicationError> for SendError {
    fn from(value: DeduplicationError) -> Self {
        match value {
            DeduplicationError::TooOld => SendError::TooOld,
            DeduplicationError::CreatedInFuture { ledger_time } => {
                SendError::CreatedInFuture { ledger_time }
            }
            DeduplicationError::Duplicate { duplicate_of } => SendError::Duplicate { duplicate_of },
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(try_from = "candid::types::reference::Func")]
pub struct GetTransactionsFn {
    pub canister_id: Principal,
    pub method: String,
    pub _marker: PhantomData<(GetTransactionsArgs, GetTransactionsResult)>,
}

impl GetTransactionsFn {
    pub fn new(canister_id: Principal, method: impl Into<String>) -> Self {
        Self {
            canister_id,
            method: method.into(),
            _marker: PhantomData,
        }
    }
}

impl From<GetTransactionsFn> for candid::Func {
    fn from(archive_fn: GetTransactionsFn) -> Self {
        let principal = Principal::try_from(archive_fn.canister_id.as_ref())
            .expect("could not deserialize principal");
        Self {
            principal,
            method: archive_fn.method,
        }
    }
}

impl TryFrom<candid::Func> for GetTransactionsFn {
    type Error = String;
    fn try_from(func: candid::types::reference::Func) -> Result<Self, Self::Error> {
        let canister_id = Principal::try_from(func.principal.as_slice())
            .map_err(|e| format!("principal is not a canister id: {}", e))?;
        Ok(GetTransactionsFn {
            canister_id,
            method: func.method,
            _marker: PhantomData,
        })
    }
}

impl CandidType for GetTransactionsFn {
    fn _ty() -> candid::types::Type {
        candid::func!((GetTransactionsArgs) -> (GetTransactionsResult) query)
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        candid::types::reference::Func::from(self.clone()).idl_serialize(serializer)
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetTransactionsArg {
    pub start: Nat,
    pub length: Nat,
}

pub type GetTransactionsArgs = Vec<GetTransactionsArg>;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransactionWithId {
    pub id: Nat,
    pub transaction: Value,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ArchivedTransactions {
    pub args: GetTransactionsArgs,
    pub callback: GetTransactionsFn,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetTransactionsResult {
    // Total number of transactions in the
    // transaction log.
    pub log_length: Nat,

    pub transactions: Vec<TransactionWithId>,

    pub archived_transactions: Vec<ArchivedTransactions>,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct DataCertificate {
    pub certificate: serde_bytes::ByteBuf,

    // CBOR encoded hash_tree
    pub hash_tree: serde_bytes::ByteBuf,
}
