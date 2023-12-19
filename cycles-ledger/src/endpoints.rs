use std::marker::PhantomData;

use candid::{CandidType, Deserialize, Nat, Principal};
use ic_cdk::api::{call::RejectionCode, management_canister::provisional::CanisterSettings};
use icrc_ledger_types::{
    icrc::generic_value::Value,
    icrc1::{
        account::{Account, Subaccount},
        transfer::{BlockIndex, Memo},
    },
};
use serde::Serialize;

use crate::config::Config;

#[derive(Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub enum ChangeIndexId {
    Unset,
    SetTo(Principal),
}

impl From<ChangeIndexId> for Option<Principal> {
    fn from(value: ChangeIndexId) -> Self {
        match value {
            ChangeIndexId::Unset => None,
            ChangeIndexId::SetTo(index_id) => Some(index_id),
        }
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpgradeArgs {
    pub max_transactions_per_request: Option<u64>,
    pub change_index_id: Option<ChangeIndexId>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum LedgerArgs {
    Init(Config),
    Upgrade(Option<UpgradeArgs>),
}

pub type NumCycles = Nat;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DepositArg {
    pub to: Account,
    pub memo: Option<Memo>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DepositResult {
    pub block_index: Nat,
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

#[derive(Default, Debug, Clone, CandidType, Serialize, Deserialize, PartialEq, Eq)]
pub struct CmcCreateCanisterArgs {
    pub subnet_selection: Option<SubnetSelection>,
    pub settings: Option<CanisterSettings>,
}

#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct SubnetFilter {
    pub subnet_type: Option<String>,
}

#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub enum SubnetSelection {
    /// Choose a random subnet that satisfies the specified properties
    Filter(SubnetFilter),
    /// Choose a specific subnet
    Subnet { subnet: Principal },
}

#[derive(Default, Debug, Clone, CandidType, Deserialize, PartialEq, Eq)]
pub struct CreateCanisterArgs {
    #[serde(default)]
    pub from_subaccount: Option<Subaccount>,
    #[serde(default)]
    pub created_at_time: Option<u64>,
    /// Amount of cycles used to create the canister.
    /// The new canister will have `amount - canister creation fee` cycles when created.
    pub amount: NumCycles,
    #[serde(default)]
    pub creation_args: Option<CmcCreateCanisterArgs>,
}

/// Error for create_canister endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub enum CmcCreateCanisterError {
    Refunded {
        refund_amount: u128,
        create_error: String,
    },
    RefundFailed {
        create_error: String,
        refund_error: String,
    },
}

/// Error for create_canister endpoint
#[derive(Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub enum CreateCanisterError {
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
        canister_id: Option<Principal>,
    },
    FailedToCreate {
        fee_block: Option<Nat>,
        refund_block: Option<Nat>,
        error: String,
    },
    GenericError {
        error_code: Nat,
        message: String,
    },
}

impl CreateCanisterError {
    pub const BAD_FEE_ERROR: u64 = 100_001;
}

#[derive(Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct CreateCanisterSuccess {
    pub block_id: Nat,
    pub canister_id: Principal,
}
