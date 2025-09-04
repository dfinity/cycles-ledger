#![allow(deprecated)]

use std::{fmt::Display, marker::PhantomData};

use candid::{CandidType, Deserialize, Nat, Principal};
use ic_cdk::api::call::RejectionCode;
use icrc_ledger_types::{
    icrc::generic_value::Value,
    icrc1::{
        account::{Account, Subaccount},
        transfer::{BlockIndex, Memo},
    },
};
use serde::Serialize;

use crate::{config::Config, storage::Block};

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
    pub max_blocks_per_request: Option<u64>,
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
pub struct WithdrawArgs {
    #[serde(default)]
    pub from_subaccount: Option<Subaccount>,
    pub to: Principal,
    #[serde(default)]
    pub created_at_time: Option<u64>,
    pub amount: NumCycles,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WithdrawFromArgs {
    #[serde(default)]
    pub spender_subaccount: Option<Subaccount>,
    pub from: Account,
    pub to: Principal,
    #[serde(default)]
    pub created_at_time: Option<u64>,
    pub amount: NumCycles,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum WithdrawError {
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
    FailedToWithdraw {
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

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum WithdrawFromError {
    InsufficientFunds {
        balance: NumCycles,
    },
    InsufficientAllowance {
        allowance: NumCycles,
    },
    TooOld,
    CreatedInFuture {
        ledger_time: u64,
    },
    TemporarilyUnavailable,
    Duplicate {
        duplicate_of: BlockIndex,
    },
    FailedToWithdrawFrom {
        withdraw_from_block: Option<BlockIndex>,
        refund_block: Option<BlockIndex>,
        approval_refund_block: Option<BlockIndex>,
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
pub struct GetBlocksFn {
    pub canister_id: Principal,
    pub method: String,
    pub _marker: PhantomData<(GetBlocksArgs, GetBlocksResult)>,
}

impl GetBlocksFn {
    pub fn new(canister_id: Principal, method: impl Into<String>) -> Self {
        Self {
            canister_id,
            method: method.into(),
            _marker: PhantomData,
        }
    }
}

impl From<GetBlocksFn> for candid::Func {
    fn from(archive_fn: GetBlocksFn) -> Self {
        let principal = Principal::try_from(archive_fn.canister_id.as_ref())
            .expect("could not deserialize principal");
        Self {
            principal,
            method: archive_fn.method,
        }
    }
}

impl TryFrom<candid::Func> for GetBlocksFn {
    type Error = String;
    fn try_from(func: candid::types::reference::Func) -> Result<Self, Self::Error> {
        let canister_id = Principal::try_from(func.principal.as_slice())
            .map_err(|e| format!("principal is not a canister id: {}", e))?;
        Ok(GetBlocksFn {
            canister_id,
            method: func.method,
            _marker: PhantomData,
        })
    }
}

impl CandidType for GetBlocksFn {
    fn _ty() -> candid::types::Type {
        candid::func!((GetBlocksArgs) -> (GetBlocksResult) query)
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        candid::types::reference::Func::from(self.clone()).idl_serialize(serializer)
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetBlocksArg {
    pub start: Nat,
    pub length: Nat,
}

pub type GetBlocksArgs = Vec<GetBlocksArg>;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BlockWithId {
    pub id: Nat,
    pub block: Value,
}

impl Display for BlockWithId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let block = Block::from_value(self.block.to_owned()).unwrap();
        write!(f, "BlockWithId {{")?;
        write!(f, " id: {}", self.id)?;
        write!(f, ", block: {}", block)?;
        write!(f, "}}")
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ArchivedBlocks {
    pub args: GetBlocksArgs,
    pub callback: GetBlocksFn,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetBlocksResult {
    // Total number of blocks in the
    // block log.
    pub log_length: Nat,

    pub blocks: Vec<BlockWithId>,

    pub archived_blocks: Vec<ArchivedBlocks>,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct DataCertificate {
    pub certificate: serde_bytes::ByteBuf,

    // CBOR encoded hash_tree
    pub hash_tree: serde_bytes::ByteBuf,
}

/// Custom CanisterSettings type that only includes fields relevant to cycles-ledger users
#[derive(Default, Debug, Clone, CandidType, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanisterSettings {
    pub controllers: Option<Vec<Principal>>,
    pub compute_allocation: Option<Nat>,
    pub memory_allocation: Option<Nat>,
    pub freezing_threshold: Option<Nat>,
    pub reserved_cycles_limit: Option<Nat>,
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

#[derive(Debug, Clone, CandidType, Deserialize, PartialEq, Eq)]
pub struct CreateCanisterFromArgs {
    pub from: Account,
    #[serde(default)]
    pub spender_subaccount: Option<Subaccount>,
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

/// Error for create_canister endpoint
#[derive(Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub enum CreateCanisterFromError {
    InsufficientFunds {
        balance: NumCycles,
    },
    InsufficientAllowance {
        allowance: NumCycles,
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
    FailedToCreateFrom {
        create_from_block: Option<BlockIndex>,
        refund_block: Option<BlockIndex>,
        approval_refund_block: Option<BlockIndex>,
        rejection_code: RejectionCode,
        rejection_reason: String,
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

#[derive(Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct SupportedBlockType {
    pub block_type: String,
    pub url: String,
}

#[derive(Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct GetArchivesArgs {
    pub from: Option<Principal>,
}

#[derive(Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct GetArchivesResult {
    pub canister_id: Principal,
    pub start: Nat,
    pub end: Nat,
}
