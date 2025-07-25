use crate::config::{Config, REMOTE_FUTURE};
use crate::endpoints::{
    CmcCreateCanisterArgs, CmcCreateCanisterError, CreateCanisterError, CreateCanisterFromError,
    CreateCanisterSuccess, DataCertificate, DepositResult, WithdrawError, WithdrawFromError,
};
use crate::logs::{P0, P1};
use crate::memo::{encode_withdraw_memo, validate_memo};
use crate::{
    ciborium_to_generic_value, compact_account,
    config::{self, MAX_MEMO_LENGTH},
    endpoints::{BlockWithId, GetBlocksArg, GetBlocksArgs, GetBlocksResult},
    generic_to_ciborium_value,
};
use anyhow::{anyhow, bail, Context};
use candid::{Nat, Principal};
use ic_canister_log::log;
use ic_cdk::api::call::{call_with_payment128, RejectionCode};
use ic_cdk::api::management_canister::main::deposit_cycles;
use ic_cdk::api::management_canister::provisional::{CanisterIdRecord, CanisterSettings};
use ic_cdk::api::set_certified_data;
use ic_certified_map::{AsHashTree, RbTree};
use ic_stable_structures::{
    cell::Cell as StableCell,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap, StableLog, Storable,
};
use icrc_ledger_types::icrc2::approve::ApproveError;
use icrc_ledger_types::icrc2::transfer_from::TransferFromError;
use icrc_ledger_types::{
    icrc::generic_value::Value,
    icrc1::{
        account::Account,
        transfer::{BlockIndex, Memo},
    },
    icrc103::get_allowances::{Allowance, Allowances},
};
use num_traits::{ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Display;

const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);
const BALANCES_MEMORY_ID: MemoryId = MemoryId::new(3);
const APPROVALS_MEMORY_ID: MemoryId = MemoryId::new(4);
const EXPIRATION_QUEUE_MEMORY_ID: MemoryId = MemoryId::new(5);
const TRANSACTION_HASH_MEMORY_ID: MemoryId = MemoryId::new(6);
const TRANSACTION_TIMESTAMP_MEMORY_ID: MemoryId = MemoryId::new(7);
const CONFIG_MEMORY_ID: MemoryId = MemoryId::new(8);

pub const CMC_PRINCIPAL: Principal = Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 4, 1, 1]);

type VMem = VirtualMemory<DefaultMemoryImpl>;

pub type AccountKey = (Principal, [u8; 32]);
pub type BlockLog = StableLog<Cbor<Block>, VMem, VMem>;
pub type Balances = StableBTreeMap<AccountKey, u128, VMem>;
/// maps tx hash to block index and an optional principal, which is set if the tx produced a canister
pub type TransactionHashes = StableBTreeMap<Hash, (u64, Option<Principal>), VMem>;
pub type TransactionTimeStampKey = (u64, u64);
/// maps time stamp to block index
pub type TransactionTimeStamps = StableBTreeMap<TransactionTimeStampKey, (), VMem>;
pub type ConfigCell = StableCell<Config, VMem>;

pub type ApprovalKey = (AccountKey, AccountKey);
pub type Approvals = StableBTreeMap<ApprovalKey, (u128, u64), VMem>;
pub type ExpirationQueue = StableBTreeMap<(u64, ApprovalKey), (), VMem>;

pub type Hash = [u8; 32];

pub struct Cache {
    // The hash of the last block.
    pub phash: Option<Hash>,
    // The total supply of cycles.
    pub total_supply: u128,
    // The hash tree that is used to certify the chain.
    // It contains the hash and the index of the
    // last block on the chain.
    pub hash_tree: RbTree<&'static str, Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(try_from = "FlattenedTransaction")]
#[serde(into = "FlattenedTransaction")]
pub struct Transaction {
    pub operation: Operation,
    pub created_at_time: Option<u64>,
    pub memo: Option<Memo>,
}

fn account_to_value(account: Account) -> Value {
    let mut components = vec![Value::blob(account.owner.as_slice())];
    if let Some(sub) = account.subaccount {
        components.push(Value::blob(sub))
    }
    Value::Array(components)
}

impl Transaction {
    pub fn to_value(self) -> Value {
        let mut map = BTreeMap::new();
        if let Some(created_at_time) = self.created_at_time {
            map.insert(
                "ts".to_string(),
                Value::Nat(candid::Nat::from(created_at_time)),
            );
        }
        if let Some(memo) = self.memo {
            map.insert("memo".to_string(), Value::Blob(memo.0));
        }
        match self.operation {
            Operation::Mint { to, amount, fee } => {
                map.insert("op".to_string(), Value::text("mint"));
                map.insert("to".to_string(), account_to_value(to));
                map.insert("amt".to_string(), Value::Nat(candid::Nat::from(amount)));
                map.insert("fee".to_string(), Value::Nat(candid::Nat::from(fee)));
            }
            Operation::Transfer {
                from,
                to,
                spender,
                amount,
                fee,
            } => {
                map.insert("op".to_string(), Value::text("xfer"));
                map.insert("from".to_string(), account_to_value(from));
                map.insert("to".to_string(), account_to_value(to));
                if let Some(spender) = spender {
                    map.insert("spender".to_string(), account_to_value(spender));
                }
                map.insert("amt".to_string(), Value::Nat(candid::Nat::from(amount)));
                if let Some(fee) = fee {
                    map.insert("fee".to_string(), Value::Nat(candid::Nat::from(fee)));
                }
            }
            Operation::Burn {
                from,
                spender,
                amount,
            } => {
                map.insert("op".to_string(), Value::text("burn"));
                map.insert("from".to_string(), account_to_value(from));
                if let Some(spender) = spender {
                    map.insert("spender".to_string(), account_to_value(spender));
                }
                map.insert("amt".to_string(), Value::Nat(candid::Nat::from(amount)));
            }
            Operation::Approve {
                from,
                spender,
                amount,
                expected_allowance,
                expires_at,
                fee,
            } => {
                map.insert("op".to_string(), Value::text("approve"));
                map.insert("from".to_string(), account_to_value(from));
                map.insert("spender".to_string(), account_to_value(spender));
                map.insert("amt".to_string(), Value::Nat(candid::Nat::from(amount)));
                if let Some(expected_allowance) = expected_allowance {
                    map.insert(
                        "expected_allowance".to_string(),
                        Value::Nat(candid::Nat::from(expected_allowance)),
                    );
                }
                if let Some(expires_at) = expires_at {
                    map.insert(
                        "expires_at".to_string(),
                        Value::Nat(candid::Nat::from(expires_at)),
                    );
                }
                if let Some(fee) = fee {
                    map.insert("fee".to_string(), Value::Nat(candid::Nat::from(fee)));
                }
            }
        }
        Value::Map(map)
    }

    pub fn hash(&self) -> anyhow::Result<Hash> {
        let value = ciborium::Value::serialized(self).context(format!(
            "Bug: unable to convert Transaction to Ciborium Value. Transaction: {:?}",
            self
        ))?;
        ciborium_to_generic_value(&value.clone(), 0)
            .map(|v| v.hash())
            .context(format!(
                "Bug: unable to convert Ciborium Value to Value. Transaction: {:?}, Value: {:?}",
                self, value
            ))
    }
}

impl Display for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Transaction {{ ")?;
        write!(f, " ts: ")?;
        display_opt(self.created_at_time, f)?;
        write!(f, ", memo: ")?;
        display_opt(self.memo.as_ref().map(|Memo(bs)| hex::encode(bs)), f)?;
        write!(f, ", op: {}", self.operation)?;
        write!(f, " }}")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Operation {
    Mint {
        to: Account,
        amount: u128,
        // Custom non-standard fee to record the amount
        // of cycles "burned" when cycles are deposited, i.e.,
        // the diffence between the cycles deposited and
        // the cycles minted. Note that this field has
        // no effect on the balance of the `to` account.
        fee: u128,
    },
    Transfer {
        from: Account,
        to: Account,
        spender: Option<Account>,
        amount: u128,
        fee: Option<u128>,
    },
    Burn {
        from: Account,
        spender: Option<Account>,
        amount: u128,
    },
    Approve {
        from: Account,
        spender: Account,
        amount: u128,
        expected_allowance: Option<u128>,
        expires_at: Option<u64>,
        fee: Option<u128>,
    },
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approve {
                from,
                spender,
                amount,
                expected_allowance,
                expires_at,
                fee,
            } => {
                write!(f, "Approve {{")?;
                write!(f, " from: {from}")?;
                write!(f, ", spender: {spender}")?;
                write!(f, ", amount: {amount}")?;
                write!(f, ", expected_allowance: ")?;
                display_opt(expected_allowance.as_ref(), f)?;
                display_opt(expires_at.as_ref(), f)?;
                write!(f, ", fee: ")?;
                display_opt(fee.as_ref(), f)?;
                write!(f, " }}")
            }
            Self::Burn {
                from,
                spender,
                amount,
            } => {
                write!(f, "Burn {{")?;
                write!(f, " from: {from}")?;
                write!(f, ", spender: {spender:?}")?;
                write!(f, ", amount: {amount}")?;
                write!(f, " }}")
            }
            Self::Mint { to, amount, fee } => {
                write!(f, "Mint {{")?;
                write!(f, " to: {to}")?;
                write!(f, ", amount: {amount}")?;
                write!(f, ", fee: {fee}")?;
                write!(f, " }}")
            }
            Self::Transfer {
                from,
                to,
                spender,
                amount,
                fee,
            } => {
                write!(f, "Transfer {{")?;
                write!(f, " from: {from}")?;
                write!(f, ", to: {to}")?;
                write!(f, ", spender: ")?;
                display_opt(spender.as_ref(), f)?;
                write!(f, ", amount: {amount}")?;
                write!(f, ", fee: ")?;
                display_opt(fee.as_ref(), f)?;
                write!(f, " }}")
            }
        }
    }
}

// A [Transaction] but flattened meaning that [Operation]
// fields are mixed with [Transaction] fields.
// workaround to https://github.com/serde-rs/json/issues/625
#[derive(Clone, Debug, Serialize, Deserialize)]
struct FlattenedTransaction {
    // [Transaction] fields.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ts")]
    pub created_at_time: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<Memo>,

    // [Operation] fields.
    pub op: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "compact_account::opt")]
    from: Option<Account>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "compact_account::opt")]
    to: Option<Account>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "compact_account::opt")]
    spender: Option<Account>,
    #[serde(rename = "amt")]
    amount: u128,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<u128>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_allowance: Option<u128>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
}

impl TryFrom<FlattenedTransaction> for Transaction {
    type Error = String;

    fn try_from(value: FlattenedTransaction) -> Result<Self, Self::Error> {
        let operation = match value.op.as_str() {
            "burn" => Operation::Burn {
                from: value
                    .from
                    .ok_or("`from` field required for `burn` operation")?,
                spender: value.spender,
                amount: value.amount,
            },
            "mint" => Operation::Mint {
                to: value.to.ok_or("`to` field required for `mint` operation")?,
                amount: value.amount,
                fee: value
                    .fee
                    .ok_or("`fee` field required for `mint` operation")?,
            },
            "xfer" => Operation::Transfer {
                from: value
                    .from
                    .ok_or("`from` field required for `xfer` operation")?,
                spender: value.spender,
                to: value.to.ok_or("`to` field required for `xfer` operation")?,
                amount: value.amount,
                fee: value.fee,
            },
            "approve" => Operation::Approve {
                from: value
                    .from
                    .ok_or("`from` field required for `approve` operation")?,
                spender: value
                    .spender
                    .ok_or("`spender` field required for `approve` operation")?,
                amount: value.amount,
                expected_allowance: value.expected_allowance,
                expires_at: value.expires_at,
                fee: value.fee,
            },
            unknown_op => return Err(format!("Unknown op name {}", unknown_op)),
        };
        Ok(Transaction {
            operation,
            created_at_time: value.created_at_time,
            memo: value.memo,
        })
    }
}

impl From<Transaction> for FlattenedTransaction {
    fn from(t: Transaction) -> Self {
        use Operation::*;

        FlattenedTransaction {
            created_at_time: t.created_at_time,
            memo: t.memo,
            op: match &t.operation {
                Burn { .. } => "burn",
                Mint { .. } => "mint",
                Transfer { .. } => "xfer",
                Approve { .. } => "approve",
            }
            .into(),
            from: match &t.operation {
                Transfer { from, .. } | Burn { from, .. } | Approve { from, .. } => Some(*from),
                _ => None,
            },
            to: match &t.operation {
                Mint { to, .. } | Transfer { to, .. } => Some(*to),
                _ => None,
            },
            spender: match &t.operation {
                Transfer { spender, .. } => spender.to_owned(),
                Approve { spender, .. } => Some(*spender),
                Burn { spender, .. } => spender.to_owned(),
                _ => None,
            },
            amount: match &t.operation {
                Burn { amount, .. }
                | Mint { amount, .. }
                | Transfer { amount, .. }
                | Approve { amount, .. } => *amount,
            },
            fee: match &t.operation {
                Transfer { fee, .. } | Approve { fee, .. } => fee.to_owned(),
                Mint { fee, .. } => Some(fee.to_owned()),
                _ => None,
            },
            expected_allowance: match &t.operation {
                Approve {
                    expected_allowance, ..
                } => expected_allowance.to_owned(),
                _ => None,
            },
            expires_at: match &t.operation {
                Approve { expires_at, .. } => expires_at.to_owned(),
                _ => None,
            },
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Block {
    #[serde(rename = "tx")]
    pub transaction: Transaction,
    #[serde(rename = "ts")]
    pub timestamp: u64,
    #[serde(default, with = "phash", skip_serializing_if = "Option::is_none")]
    pub phash: Option<[u8; 32]>,
    #[serde(rename = "fee")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_fee: Option<u128>,
}

impl Block {
    pub fn from_value(value: Value) -> anyhow::Result<Self> {
        let cvalue = generic_to_ciborium_value(&value, 0).context(format!(
            "Bug: unable to convert Value to Ciborium Value.\nValue: {:?}",
            value
        ))?;
        ciborium::value::Value::deserialized(&cvalue).context(format!(
            "Bug: unable to convert Ciborium Value to Block.\nCiborium Value: {:?}\nValue: {:?}",
            cvalue, value
        ))
    }

    pub fn to_value(self) -> Value {
        let mut map = BTreeMap::new();
        map.insert("tx".to_string(), self.transaction.to_value());
        map.insert(
            "ts".to_string(),
            Value::Nat(candid::Nat::from(self.timestamp)),
        );
        if let Some(phash) = self.phash {
            map.insert("phash".to_string(), Value::blob(phash));
        }
        if let Some(effective_fee) = self.effective_fee {
            map.insert(
                "fee".to_string(),
                Value::Nat(candid::Nat::from(effective_fee)),
            );
        }
        Value::Map(map)
    }

    pub fn hash(self) -> Hash {
        self.to_value().hash()
    }
}

fn display_opt<T>(opt: Option<T>, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
where
    T: Display,
{
    match opt {
        None => write!(f, "None"),
        Some(t) => write!(f, "Some({t})"),
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Block {{ ")?;
        write!(f, "phash: ")?;
        display_opt(self.phash.map(hex::encode), f)?;
        write!(f, ", ts: {}", self.timestamp)?;
        write!(f, ", fee: ")?;
        display_opt(self.effective_fee, f)?;
        write!(f, ", tx: {}, ", self.transaction)?;
        write!(f, " }}")
    }
}

pub struct State {
    pub blocks: BlockLog,
    pub balances: Balances,
    pub approvals: Approvals,
    pub expiration_queue: ExpirationQueue,
    pub transaction_hashes: TransactionHashes,
    pub transaction_timestamps: TransactionTimeStamps,
    pub config: ConfigCell,
    // In-memory cache dropped on each upgrade.
    pub cache: Cache,
}

impl State {
    pub fn last_block_hash(&self) -> Option<Hash> {
        self.cache.phash
    }

    pub fn total_supply(&self) -> u128 {
        self.cache.total_supply
    }

    // Return `Ok` if the `account` balance doesn't overflow
    // when credited the `amount`, `Err` otherwise.
    pub fn check_credit_to_account(&self, account: &Account, amount: u128) -> anyhow::Result<u128> {
        let account_key = to_account_key(account);
        let old_balance = self.balances.get(&account_key).unwrap_or_default();
        old_balance
            .checked_add(amount)
            .context("Overflow while changing the account balance")
    }

    // Return `Ok` if total supply doesn't overflow
    // when increased of `amount`, `Err` otherwise.
    pub fn check_total_supply_increase(&self, amount: u128) -> anyhow::Result<u128> {
        self.total_supply()
            .checked_add(amount)
            .context("Overflow while changing the total supply")
    }

    // Combination of `check_credit_to_account` and `check_total_supply_increase`
    pub fn check_credit(&self, account: &Account, amount: u128) -> anyhow::Result<()> {
        let _ = self.check_credit_to_account(account, amount)?;
        let _ = self.check_total_supply_increase(amount)?;
        Ok(())
    }

    // Return `Ok` with the new balance if the `account`
    // balance has enough funds,
    // `Err` with the current balance otherwise
    pub fn check_debit_from_account(&self, account: &Account, amount: u128) -> Result<u128, u128> {
        let account_key = to_account_key(account);
        let old_balance = self.balances.get(&account_key).unwrap_or_default();
        old_balance.checked_sub(amount).ok_or(old_balance)
    }

    // Return `Ok` if total supply doesn't underflow
    // when decreased of `amount`, `Err` otherwise
    pub fn check_total_supply_decrease(&self, amount: u128) -> anyhow::Result<u128> {
        self.total_supply()
            .checked_sub(amount)
            .context("Underflow while changing the total supply")
    }

    /// Increases the balance of an account of the given amount.
    /// Returns an error is either the account balance or the
    /// total supply overflow.
    ///
    /// Invariant: if `self.check_credit_to_account(account, amount).is_ok()`
    /// and `self.check_total_supply_increase(amount).is_ok()` then
    /// `self.credit(account, amount).is_ok()`
    pub fn credit(&mut self, account: &Account, amount: u128) -> anyhow::Result<u128> {
        let account_key = to_account_key(account);
        let old_balance = self.balances.get(&account_key).unwrap_or_default();
        let new_balance = old_balance
            .checked_add(amount)
            .context("Overflow while changing the account balance")?;
        self.cache.total_supply = self
            .total_supply()
            .checked_add(amount)
            .context("Overflow while changing the total supply")?;
        self.balances.insert(account_key, new_balance);
        Ok(new_balance)
    }

    /// Decreases the balance of an account of the given amount.
    pub fn debit(&mut self, account: &Account, amount: u128) -> anyhow::Result<u128> {
        let account_key = to_account_key(account);
        let old_balance = self.balances.get(&account_key).unwrap_or_default();
        let new_balance = old_balance
            .checked_sub(amount)
            .context("Underflow while changing the account balance")?;
        self.cache.total_supply = self
            .total_supply()
            .checked_sub(amount)
            .context("Underflow while changing the total supply")?;
        if new_balance == 0 {
            self.balances.remove(&account_key);
        } else {
            self.balances.insert(account_key, new_balance);
        }
        Ok(new_balance)
    }

    pub fn get_tip_certificate(&self) -> Option<DataCertificate> {
        let certificate = match ic_cdk::api::data_certificate() {
            Some(certificate) => ByteBuf::from(certificate),
            None => return None,
        };
        let mut hash_tree_buf = vec![];
        ciborium::ser::into_writer(
            &self
                .cache
                .hash_tree
                .value_range(b"last_block_hash", b"last_block_index"),
            &mut hash_tree_buf,
        )
        .expect(
            "Bug: unable to write last_block_hash and last_block_index values in the hash_tree",
        );
        let hash_tree = ByteBuf::from(hash_tree_buf);
        Some(DataCertificate {
            certificate,
            hash_tree,
        })
    }

    /// Returns the root hash of the certified ledger state.
    /// The canister code must call [set_certified_data] with the value this function returns after
    /// each successful modification of the ledger.
    pub fn root_hash(&self) -> Hash {
        self.cache.hash_tree.root_hash()
    }

    pub fn compute_last_block_hash_and_hash_tree(
        blocks: &BlockLog,
    ) -> (Option<Hash>, RbTree<&'static str, Vec<u8>>) {
        let mut hash_tree = RbTree::new();
        let n = blocks.len();
        if n == 0 {
            return (None, hash_tree);
        }
        let last_block_hash = blocks.get(n - 1).unwrap().to_owned().hash();
        populate_last_block_hash_and_hash_tree(&mut hash_tree, n - 1, last_block_hash);
        (Some(last_block_hash), hash_tree)
    }

    pub fn emit_block(&mut self, b: Block) -> Hash {
        let hash = b.clone().hash();
        self.cache.phash = Some(hash);
        let tx_hash = b.transaction.hash().unwrap();
        let created_at_time = b.transaction.created_at_time;
        self.blocks
            .append(&Cbor(b))
            .expect("failed to append a block");

        // Change the certified data to point to the new block at the end of the list of blocks
        let block_idx = self.blocks.len() - 1;
        populate_last_block_hash_and_hash_tree(&mut self.cache.hash_tree, block_idx, hash);
        set_certified_data(&self.root_hash());

        if let Some(ts) = created_at_time {
            // Add block index to the list of transactions and set the hash as its key
            self.transaction_hashes
                .insert(tx_hash, (self.blocks.len() - 1, None));
            self.transaction_timestamps
                .insert((ts, self.blocks.len() - 1), ());
        }

        hash
    }

    fn compute_total_supply(balances: &Balances) -> u128 {
        let mut total_supply = 0;
        for (_, balance) in balances.iter() {
            total_supply += balance;
        }
        total_supply
    }
}

thread_local! {
    /// Static memory manager to manage the memory available for stable structures.
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static STATE: RefCell<State> = MEMORY_MANAGER.with(|cell| {
        let mm = cell.borrow();
        let blocks = BlockLog::init(
                mm.get(BLOCK_LOG_INDEX_MEMORY_ID),
                mm.get(BLOCK_LOG_DATA_MEMORY_ID)
            ).expect("failed to initialize the block log");
        let balances = Balances::init(mm.get(BALANCES_MEMORY_ID));
        let (phash, hash_tree) = State::compute_last_block_hash_and_hash_tree(&blocks);
        let config = ConfigCell::init(mm.get(CONFIG_MEMORY_ID), Config::default())
            .expect("failed to initialize the config cell");

        RefCell::new(State {
            cache: Cache {
                phash,
                hash_tree,
                total_supply: State::compute_total_supply(&balances),
            },
            blocks,
            balances,
            approvals: Approvals::init(mm.get(APPROVALS_MEMORY_ID)),
            transaction_hashes: TransactionHashes::init(mm.get(TRANSACTION_HASH_MEMORY_ID)),
            transaction_timestamps: TransactionTimeStamps::init(mm.get(TRANSACTION_TIMESTAMP_MEMORY_ID)),
            expiration_queue: ExpirationQueue::init(mm.get(EXPIRATION_QUEUE_MEMORY_ID)),
            config,
        })
    });
}

pub fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|cell| f(&cell.borrow()))
}

pub fn mutate_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|cell| f(&mut cell.borrow_mut()))
}

pub fn read_config<R>(f: impl FnOnce(&Config) -> R) -> R {
    read_state(|state| f(state.config.get()))
}

pub fn mutate_config<R>(f: impl FnOnce(&mut Config) -> R) -> R {
    mutate_state(|state| {
        let mut config = state.config.get().to_owned();
        let r = f(&mut config);
        state
            .config
            .set(config)
            .expect("Failed to change configuration");
        r
    })
}

// Prune old approval and transactions
// and performs a sanity check on the
// current state of the ledger.
pub fn prune(now: u64) {
    mutate_state(|state| {
        prune_approvals(now, state, config::APPROVE_PRUNE_LIMIT);
        prune_transactions(now, state, config::TRANSACTION_PRUNE_LIMIT);
    });
    read_state(check_invariants);
}

fn check_invariants(s: &State) {
    if s.expiration_queue.len() > s.approvals.len() {
        log!(
            P0,
            "expiration_queue len ({}) larger than approvals len ({})",
            s.expiration_queue.len(),
            s.approvals.len()
        )
    }
}

/// The maximum number of bytes a 64-bit number can occupy when encoded in LEB128.
const MAX_U64_ENCODING_BYTES: usize = 10;

pub fn populate_last_block_hash_and_hash_tree(
    hash_tree: &mut RbTree<&'static str, Vec<u8>>,
    last_block_index: u64,
    last_block_hash: Hash,
) {
    let mut last_block_index_buf = Vec::with_capacity(MAX_U64_ENCODING_BYTES);
    leb128::write::unsigned(&mut last_block_index_buf, last_block_index).unwrap();
    hash_tree.insert("last_block_index", last_block_index_buf.to_vec());
    hash_tree.insert("last_block_hash", last_block_hash.to_vec());
}

#[derive(Default)]
pub struct Cbor<T>(pub T)
where
    T: serde::Serialize + serde::de::DeserializeOwned;

impl<T> std::ops::Deref for Cbor<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Storable for Cbor<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        ciborium::ser::into_writer(&self.0, &mut buf).unwrap();
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(ciborium::de::from_reader(bytes.as_ref()).unwrap())
    }

    const BOUND: ic_stable_structures::storable::Bound =
        ic_stable_structures::storable::Bound::Unbounded;
}

pub fn to_account_key(account: &Account) -> AccountKey {
    (account.owner, *account.effective_subaccount())
}

pub fn to_account_pair(approval_key: &ApprovalKey) -> (Account, Account) {
    let account1 = Account {
        owner: approval_key.0 .0,
        subaccount: Some(approval_key.0 .1),
    };
    let account2 = Account {
        owner: approval_key.1 .0,
        subaccount: Some(approval_key.1 .1),
    };
    (account1, account2)
}

pub fn balance_of(account: &Account) -> u128 {
    read_state(|s| s.balances.get(&to_account_key(account)).unwrap_or_default())
}

pub fn deposit(
    to: Account,
    amount: u128,
    memo: Option<Memo>,
    now: u64,
) -> anyhow::Result<DepositResult> {
    // check that the amount is at least the fee plus one
    let amount_to_mint = match amount.checked_sub(crate::config::FEE) {
        None => {
            bail!(
                "The requested amount {} to be deposited is \
                less than the cycles ledger fee: {}",
                amount,
                crate::config::FEE
            )
        }
        Some(0) => {
            bail!(
                "Cannot deposit 0 cycles (amount: {}, cycles ledger fee: {})",
                amount,
                crate::config::FEE
            )
        }
        Some(amount_to_mint) => amount_to_mint,
    };

    let block_index = mint(to, amount_to_mint, memo, now)?;

    prune(now);

    Ok(DepositResult {
        block_index: Nat::from(block_index),
        balance: Nat::from(balance_of(&to)),
    })
}

pub fn mint(to: Account, amount: u128, memo: Option<Memo>, now: u64) -> anyhow::Result<u64> {
    if let Err(err) = read_state(|state| state.check_credit(&to, amount)) {
        // This should not happen as the number of total cycles
        // a canister can deposit should never exceed the max.
        // If this happens then the error is logged and returned
        // to the caller.
        let err = err.context(format!("Unable to mint {} cycles to {}", amount, to));
        log!(P0, "{:#}", err);
        return Err(err);
    }

    // we are not checking for duplicates, since mint is executed with created_at_time: None
    let block_index = process_transaction(
        Transaction {
            operation: Operation::Mint {
                to,
                amount,
                fee: crate::config::FEE,
            },
            created_at_time: None,
            memo,
        },
        now,
    )?;

    if let Err(err) = mutate_state(|state| state.credit(&to, amount)) {
        // This should not happen because of the checks before
        // and within `process_transaction`.
        // If this happens then log an error and panic so that
        // the state is reset to a valid one.
        let err = err.context(format!("Unable to credit {to} to {amount}"));
        ic_cdk::trap(&format!("{err:#}"));
    }

    Ok(block_index)
}

const DENIED_PRINCIPALS: [Principal; 2] =
    [Principal::anonymous(), Principal::management_canister()];

fn is_denied_account_owner(principal: &Principal) -> bool {
    DENIED_PRINCIPALS.iter().any(|denied| denied == principal)
}

#[allow(clippy::too_many_arguments)]
pub fn transfer(
    from: Account,
    to: Account,
    spender: Option<Account>,
    amount: u128,
    memo: Option<Memo>,
    now: u64,
    created_at_time: Option<u64>,
    suggested_fee: Option<u128>,
) -> Result<Nat, TransferFromError> {
    use TransferFromError::*;

    let transaction = Transaction {
        operation: Operation::Transfer {
            from,
            to,
            spender,
            amount,
            fee: suggested_fee,
        },
        created_at_time,
        memo,
    };
    check_duplicate(&transaction)?;

    // check that no account is owned by a denied principal
    if is_denied_account_owner(&from.owner) {
        return Err(transfer_from::denied_owner(from));
    }
    if is_denied_account_owner(&to.owner) {
        return Err(transfer_from::denied_owner(to));
    }
    if let Some(spender) = spender {
        if is_denied_account_owner(&spender.owner) {
            return Err(transfer_from::denied_owner(spender));
        }
    }

    // if `amount` + `fee` overflows then the user doesn't have enough funds
    let Some(amount_with_fee) = amount.checked_add(config::FEE) else {
        return Err(InsufficientFunds {
            balance: balance_of(&from).into(),
        });
    };

    // check allowance
    if let Some(spender) = spender {
        if spender != from {
            read_state(|state| check_allowance(state, &from, &spender, amount_with_fee, now))?;
        }
    }

    // Check that the `from` account has enough funds
    read_state(|state| state.check_debit_from_account(&from, amount_with_fee)).map_err(
        |balance| TransferFromError::InsufficientFunds {
            balance: balance.into(),
        },
    )?;

    // sanity check that the `to` account balance won't overflow
    read_state(|state| state.check_credit_to_account(&to, amount))
        .map_err(transfer_from::anyhow_error)?;

    // sanity check that the total_supply won't underflow
    read_state(|state| state.check_total_supply_decrease(config::FEE))
        .with_context(|| {
            format!(
                "Unable to transfer {} cycles from {} to {} (spender: {:?})",
                amount, from, to, spender
            )
        })
        .map_err(transfer_from::anyhow_error)?;

    let block_index = process_transaction(transaction.clone(), now)?;

    // The operations below should not return an error because of the checks
    // before and inside `process_transaction`.
    // If an error happens, then log it and panic so that
    // the state is reset to a valid one.

    if let Some(spender) = spender {
        if spender != from {
            if let Err(err) =
                mutate_state(|state| use_allowance(state, &from, &spender, amount_with_fee, now))
            {
                ic_cdk::trap(&format!("Unable to perform transfer {transaction}: {err}"));
            }
        }
    }

    if let Err(err) = mutate_state(|state| state.debit(&from, amount_with_fee)) {
        let err = err.context(format!("Unable to perform transfer {transaction}"));
        ic_cdk::trap(&format!("{err:#}"));
    };

    if let Err(err) = mutate_state(|state| state.credit(&to, amount)) {
        let err = err.context(format!("Unable to perform transfer {transaction}"));
        ic_cdk::trap(&format!("{err:#}"));
    };

    Ok(Nat::from(block_index))
}

#[allow(clippy::too_many_arguments)]
pub fn approve(
    from: Account,
    spender: Account,
    amount: u128,
    memo: Option<Memo>,
    now: u64,
    created_at_time: Option<u64>,
    suggested_fee: Option<u128>,
    expected_allowance: Option<u128>,
    expires_at: Option<u64>,
) -> Result<Nat, ApproveError> {
    let transaction = Transaction {
        operation: Operation::Approve {
            from,
            spender,
            amount,
            expected_allowance,
            expires_at,
            fee: suggested_fee,
        },
        created_at_time,
        memo,
    };
    check_duplicate(&transaction)?;

    // check that this isn't a self approval
    if from.owner == spender.owner {
        ic_cdk::trap("self approval is not allowed");
    }

    // check that no account is owned by a denied principal
    if is_denied_account_owner(&from.owner) {
        return Err(approve::denied_owner(from));
    }
    if is_denied_account_owner(&spender.owner) {
        return Err(approve::denied_owner(spender));
    }

    // check that the `expected_allowance` matches the current one
    let allowance = allowance(&from, &spender, now).0;
    if expected_allowance.is_some() && expected_allowance != Some(allowance) {
        return Err(ApproveError::AllowanceChanged {
            current_allowance: Nat::from(allowance),
        });
    }

    // check that the `from` account has enough funds to pay the fee
    let balance = balance_of(&from);
    if balance < config::FEE {
        return Err(ApproveError::InsufficientFunds {
            balance: Nat::from(balance),
        });
    }

    // check that the expiration is in the future
    if expires_at.unwrap_or(REMOTE_FUTURE) <= now {
        return Err(ApproveError::Expired { ledger_time: now });
    }

    // sanity check that the total_supply won't underflow
    read_state(|state| state.check_total_supply_decrease(config::FEE))
        .with_context(|| {
            format!(
                "Unable to approve {} cycles from {} to spender {}",
                amount, from, spender
            )
        })
        .map_err(approve::anyhow_error)?;

    let block_index = process_transaction(transaction.clone(), now)?;

    // The operations below should not return an error because of the checks
    // before and inside `process_transaction`.
    // If an error happens, then log it and panic so that
    // the state is reset to a valid one.

    mutate_state(|state| record_approval(state, &from, &spender, amount, expires_at));

    if let Err(err) = mutate_state(|state| state.debit(&from, crate::config::FEE)) {
        let err = err.context(format!("Unable to approve {transaction}"));
        ic_cdk::trap(&format!("{err:#}"));
    }

    Ok(Nat::from(block_index))
}

#[derive(Debug)]
enum ProcessTransactionError {
    BadFee {
        expected_fee: u128,
    },
    Duplicate {
        duplicate_of: u64,
        canister_id: Option<Principal>,
    },
    InvalidCreatedAtTime(CreatedAtTimeValidationError),
    GenericError(anyhow::Error),
}

impl std::error::Error for ProcessTransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::GenericError(err) => Some(err.as_ref()),
            _ => None,
        }
    }

    fn description(&self) -> &str {
        // this method is deprecated and not used
        "Error while processing transaction"
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
}

impl std::fmt::Display for ProcessTransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadFee { expected_fee } => {
                write!(f, "Invalid fee, expected fee is {}", expected_fee)
            }
            Self::Duplicate { duplicate_of, .. } => write!(
                f,
                "Input transaction is a duplicate of transaction at index {}",
                duplicate_of
            ),
            Self::InvalidCreatedAtTime(err) => write!(f, "Invalid created_at_time: {:?}", err),
            Self::GenericError(err) => write!(f, "{:#}", err),
        }
    }
}

impl From<CreatedAtTimeValidationError> for ProcessTransactionError {
    fn from(value: CreatedAtTimeValidationError) -> Self {
        Self::InvalidCreatedAtTime(value)
    }
}

impl From<anyhow::Error> for ProcessTransactionError {
    fn from(error: anyhow::Error) -> Self {
        Self::GenericError(error)
    }
}

pub mod transfer_from {
    use candid::Nat;
    use icrc_ledger_types::{icrc1::account::Account, icrc2::transfer_from::TransferFromError};

    pub const UNKNOWN_GENERIC_ERROR: u64 = 100000;
    pub const DENIED_OWNER: u64 = 100001;
    pub const CANNOT_TRANSFER_FROM_ZERO: u64 = 100002;
    pub const EXPIRED_APPROVAL: u64 = 100003;

    pub fn anyhow_error(error: anyhow::Error) -> TransferFromError {
        unknown_generic_error(format!("{:#}", error))
    }

    pub fn denied_owner(account: Account) -> TransferFromError {
        TransferFromError::GenericError {
            error_code: Nat::from(DENIED_OWNER),
            message: format!(
                "Owner of the account {} cannot be part of transactions",
                account
            ),
        }
    }

    pub fn unknown_generic_error(message: String) -> TransferFromError {
        TransferFromError::GenericError {
            error_code: Nat::from(UNKNOWN_GENERIC_ERROR),
            message,
        }
    }

    pub fn cannot_transfer_from_zero() -> TransferFromError {
        TransferFromError::GenericError {
            error_code: Nat::from(CANNOT_TRANSFER_FROM_ZERO),
            message: "The transfer_from 0 cycles is not possible".into(),
        }
    }

    pub fn expired_approval() -> TransferFromError {
        TransferFromError::GenericError {
            error_code: Nat::from(EXPIRED_APPROVAL),
            message: "Approval has expired".into(),
        }
    }
}

mod approve {
    use candid::Nat;
    use icrc_ledger_types::{icrc1::account::Account, icrc2::approve::ApproveError};

    use super::transfer_from::DENIED_OWNER;

    pub fn anyhow_error(error: anyhow::Error) -> ApproveError {
        unknown_generic_error(format!("{:#}", error))
    }

    pub fn denied_owner(account: Account) -> ApproveError {
        ApproveError::GenericError {
            error_code: Nat::from(DENIED_OWNER),
            message: format!(
                "Owner of the account {} cannot be part of approvals",
                account
            ),
        }
    }

    pub fn unknown_generic_error(message: String) -> ApproveError {
        ApproveError::GenericError {
            error_code: Nat::from(crate::storage::transfer_from::UNKNOWN_GENERIC_ERROR),
            message,
        }
    }
}

mod withdraw {
    use candid::Nat;

    use crate::endpoints::WithdrawError;

    use super::transfer_from::UNKNOWN_GENERIC_ERROR;

    pub fn unknown_generic_error(message: String) -> WithdrawError {
        WithdrawError::GenericError {
            error_code: Nat::from(UNKNOWN_GENERIC_ERROR),
            message,
        }
    }
}

mod withdraw_from {
    use candid::Nat;

    use crate::endpoints::WithdrawFromError;

    use super::transfer_from::{CANNOT_TRANSFER_FROM_ZERO, UNKNOWN_GENERIC_ERROR};

    pub fn anyhow_error(error: anyhow::Error) -> WithdrawFromError {
        unknown_generic_error(error.to_string())
    }

    pub fn unknown_generic_error(message: String) -> WithdrawFromError {
        WithdrawFromError::GenericError {
            error_code: Nat::from(UNKNOWN_GENERIC_ERROR),
            message,
        }
    }

    pub fn cannot_withdraw_from_zero() -> WithdrawFromError {
        WithdrawFromError::GenericError {
            error_code: Nat::from(CANNOT_TRANSFER_FROM_ZERO),
            message: "The withdraw_from 0 cycles is not possible".into(),
        }
    }
}

mod create_canister {
    use candid::Nat;

    use crate::endpoints::CreateCanisterError;

    use super::transfer_from::UNKNOWN_GENERIC_ERROR;

    pub fn unknown_generic_error(message: String) -> CreateCanisterError {
        CreateCanisterError::GenericError {
            error_code: Nat::from(UNKNOWN_GENERIC_ERROR),
            message,
        }
    }
}

mod create_canister_from {
    use super::transfer_from::UNKNOWN_GENERIC_ERROR;
    use crate::endpoints::CreateCanisterFromError;
    use candid::Nat;

    pub fn anyhow_error(error: anyhow::Error) -> CreateCanisterFromError {
        unknown_generic_error(format!("{:#}", error))
    }

    pub fn unknown_generic_error(message: String) -> CreateCanisterFromError {
        CreateCanisterFromError::GenericError {
            error_code: Nat::from(UNKNOWN_GENERIC_ERROR),
            message,
        }
    }
}

impl From<ProcessTransactionError> for TransferFromError {
    fn from(error: ProcessTransactionError) -> Self {
        use ProcessTransactionError::*;

        match error {
            BadFee { expected_fee } => Self::BadFee {
                expected_fee: Nat::from(expected_fee),
            },
            Duplicate { duplicate_of, .. } => Self::Duplicate {
                duplicate_of: Nat::from(duplicate_of),
            },
            InvalidCreatedAtTime(err) => err.into(),
            GenericError(err) => transfer_from::unknown_generic_error(format!("{:#}", err)),
        }
    }
}

impl From<ProcessTransactionError> for WithdrawFromError {
    fn from(error: ProcessTransactionError) -> Self {
        use crate::storage::transfer_from::UNKNOWN_GENERIC_ERROR;
        use ProcessTransactionError::*;

        match error {
            BadFee { .. } => ic_cdk::trap("BadFee should not happen for withdraw"),
            Duplicate { duplicate_of, .. } => Self::Duplicate {
                duplicate_of: Nat::from(duplicate_of),
            },
            InvalidCreatedAtTime(err) => match err {
                CreatedAtTimeValidationError::TooOld => Self::TooOld,
                CreatedAtTimeValidationError::InTheFuture { ledger_time } => {
                    Self::CreatedInFuture { ledger_time }
                }
            },
            GenericError(err) => Self::GenericError {
                error_code: Nat::from(UNKNOWN_GENERIC_ERROR),
                message: err.to_string(),
            },
        }
    }
}

impl From<ProcessTransactionError> for ApproveError {
    fn from(error: ProcessTransactionError) -> Self {
        use ProcessTransactionError::*;

        match error {
            BadFee { expected_fee } => Self::BadFee {
                expected_fee: Nat::from(expected_fee),
            },
            Duplicate { duplicate_of, .. } => Self::Duplicate {
                duplicate_of: Nat::from(duplicate_of),
            },
            InvalidCreatedAtTime(err) => err.into(),
            GenericError(err) => approve::unknown_generic_error(format!("{:#}", err)),
        }
    }
}

impl From<ProcessTransactionError> for WithdrawError {
    fn from(error: ProcessTransactionError) -> Self {
        use ProcessTransactionError::*;

        match error {
            BadFee { expected_fee } => Self::BadFee {
                expected_fee: Nat::from(expected_fee),
            },
            Duplicate { duplicate_of, .. } => Self::Duplicate {
                duplicate_of: Nat::from(duplicate_of),
            },
            InvalidCreatedAtTime(err) => err.into(),
            GenericError(err) => withdraw::unknown_generic_error(format!("{:#}", err)),
        }
    }
}

impl From<ProcessTransactionError> for CreateCanisterError {
    fn from(error: ProcessTransactionError) -> Self {
        use ProcessTransactionError::*;

        match error {
            BadFee { expected_fee } => Self::GenericError {
                error_code: CreateCanisterError::BAD_FEE_ERROR.into(),
                message: format!(
                    "BadFee. Expected fee: {}. Should never happen.",
                    expected_fee
                ),
            },
            Duplicate {
                duplicate_of,
                canister_id,
            } => Self::Duplicate {
                duplicate_of: Nat::from(duplicate_of),
                canister_id,
            },
            InvalidCreatedAtTime(err) => err.into(),
            GenericError(err) => create_canister::unknown_generic_error(format!("{:#}", err)),
        }
    }
}

impl From<ProcessTransactionError> for CreateCanisterFromError {
    fn from(error: ProcessTransactionError) -> Self {
        use ProcessTransactionError::*;

        match error {
            BadFee { expected_fee } => Self::GenericError {
                error_code: CreateCanisterError::BAD_FEE_ERROR.into(),
                message: format!(
                    "BadFee. Expected fee: {}. Should never happen.",
                    expected_fee
                ),
            },
            Duplicate {
                duplicate_of,
                canister_id,
            } => Self::Duplicate {
                duplicate_of: Nat::from(duplicate_of),
                canister_id,
            },
            InvalidCreatedAtTime(err) => err.into(),
            GenericError(err) => create_canister_from::unknown_generic_error(format!("{:#}", err)),
        }
    }
}

#[derive(Debug)]
enum UseAllowanceError {
    CannotDeduceZero,
    ExpiredApproval,
    InsufficientAllowance { allowance: u128 },
}

impl std::fmt::Display for UseAllowanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use UseAllowanceError::*;

        match self {
            CannotDeduceZero => write!(f, "The transfer_from 0 cycles is not possible"),
            ExpiredApproval => write!(f, "Approval has expired"),
            InsufficientAllowance { allowance } => {
                write!(f, "Insufficient allowance {}", allowance)
            }
        }
    }
}

impl From<UseAllowanceError> for TransferFromError {
    fn from(value: UseAllowanceError) -> Self {
        use UseAllowanceError::*;

        match value {
            CannotDeduceZero => transfer_from::cannot_transfer_from_zero(),
            ExpiredApproval { .. } => transfer_from::expired_approval(),
            InsufficientAllowance { allowance } => Self::InsufficientAllowance {
                allowance: allowance.into(),
            },
        }
    }
}

impl From<UseAllowanceError> for WithdrawFromError {
    fn from(value: UseAllowanceError) -> Self {
        use UseAllowanceError::*;

        match value {
            CannotDeduceZero => ic_cdk::trap("CannotDeduceZero should not happen for withdraw"),
            ExpiredApproval { .. } => Self::InsufficientAllowance {
                allowance: Nat::from(0_u8),
            },
            InsufficientAllowance { allowance } => Self::InsufficientAllowance {
                allowance: allowance.into(),
            },
        }
    }
}

impl From<UseAllowanceError> for CreateCanisterFromError {
    fn from(value: UseAllowanceError) -> Self {
        use UseAllowanceError::*;

        match value {
            CannotDeduceZero => {
                ic_cdk::trap("CannotDeduceZero should not happen for create_canister")
            }
            ExpiredApproval { .. } => Self::InsufficientAllowance {
                allowance: Nat::from(0_u8),
            },
            InsufficientAllowance { allowance } => Self::InsufficientAllowance {
                allowance: allowance.into(),
            },
        }
    }
}

// Validates the suggested fee and returns the effective fee.
// If the validation fails then return Err with the expected fee.
fn validate_suggested_fee(op: &Operation) -> Result<Option<u128>, u128> {
    use Operation as Op;

    match op {
        Op::Mint { .. } => Ok(Some(0)),
        Op::Burn { .. } => Ok(Some(config::FEE)),
        Op::Transfer { fee, .. } | Op::Approve { fee, .. } => {
            if fee.is_some() && fee != &Some(config::FEE) {
                return Err(config::FEE);
            }
            Ok(fee.is_none().then_some(config::FEE))
        }
    }
}

fn check_duplicate(transaction: &Transaction) -> Result<(), ProcessTransactionError> {
    use ProcessTransactionError as PTErr;
    // sanity check that the transaction can be hashed
    let tx_hash = match transaction.hash() {
        Ok(tx_hash) => tx_hash,
        Err(err) => {
            let err = err.context(format!("Unable to process transaction {:?}", transaction));
            log!(P0, "{:#}", err);
            return Err(PTErr::from(err));
        }
    };

    // check whether transaction is a duplicate
    if let Some((block_index, maybe_canister)) =
        read_state(|state| state.transaction_hashes.get(&tx_hash))
    {
        return Err(PTErr::Duplicate {
            duplicate_of: block_index,
            canister_id: maybe_canister,
        });
    }

    Ok(())
}

fn process_transaction(transaction: Transaction, now: u64) -> Result<u64, ProcessTransactionError> {
    use ProcessTransactionError as PTErr;

    // The ICRC-1 and ICP Ledgers trap when the memo validation fails
    // so we do the same.
    if let Err(err) = validate_memo(&transaction.memo) {
        ic_cdk::trap(&err);
    }

    validate_created_at_time(&transaction.created_at_time, now)?;

    let effective_fee = validate_suggested_fee(&transaction.operation)
        .map_err(|expected_fee| PTErr::BadFee { expected_fee })?;

    let block = Block {
        transaction,
        timestamp: now,
        phash: read_state(|state| state.last_block_hash()),
        effective_fee,
    };

    let _ = mutate_state(|state| state.emit_block(block));
    let block_index = read_state(|state| state.blocks.len() - 1);

    Ok(block_index)
}

#[derive(Debug)]
pub enum CreatedAtTimeValidationError {
    TooOld,
    InTheFuture { ledger_time: u64 },
}

impl From<CreatedAtTimeValidationError> for TransferFromError {
    fn from(value: CreatedAtTimeValidationError) -> Self {
        match value {
            CreatedAtTimeValidationError::TooOld => Self::TooOld,
            CreatedAtTimeValidationError::InTheFuture { ledger_time } => {
                Self::CreatedInFuture { ledger_time }
            }
        }
    }
}

impl From<CreatedAtTimeValidationError> for WithdrawError {
    fn from(value: CreatedAtTimeValidationError) -> Self {
        match value {
            CreatedAtTimeValidationError::TooOld => Self::TooOld,
            CreatedAtTimeValidationError::InTheFuture { ledger_time } => {
                Self::CreatedInFuture { ledger_time }
            }
        }
    }
}

impl From<CreatedAtTimeValidationError> for CreateCanisterError {
    fn from(value: CreatedAtTimeValidationError) -> Self {
        match value {
            CreatedAtTimeValidationError::TooOld => Self::TooOld,
            CreatedAtTimeValidationError::InTheFuture { ledger_time } => {
                Self::CreatedInFuture { ledger_time }
            }
        }
    }
}

impl From<CreatedAtTimeValidationError> for CreateCanisterFromError {
    fn from(value: CreatedAtTimeValidationError) -> Self {
        match value {
            CreatedAtTimeValidationError::TooOld => Self::TooOld,
            CreatedAtTimeValidationError::InTheFuture { ledger_time } => {
                Self::CreatedInFuture { ledger_time }
            }
        }
    }
}

impl From<CreatedAtTimeValidationError> for ApproveError {
    fn from(value: CreatedAtTimeValidationError) -> Self {
        match value {
            CreatedAtTimeValidationError::TooOld => Self::TooOld,
            CreatedAtTimeValidationError::InTheFuture { ledger_time } => {
                Self::CreatedInFuture { ledger_time }
            }
        }
    }
}

pub fn validate_created_at_time(
    created_at_time: &Option<u64>,
    now: u64,
) -> Result<(), CreatedAtTimeValidationError> {
    let Some(created_at_time) = created_at_time else {
        return Ok(());
    };
    if created_at_time
        .saturating_add(config::TRANSACTION_WINDOW.as_nanos() as u64)
        .saturating_add(config::PERMITTED_DRIFT.as_nanos() as u64)
        < now
    {
        return Err(CreatedAtTimeValidationError::TooOld);
    }

    if created_at_time > &now.saturating_add(config::PERMITTED_DRIFT.as_nanos() as u64) {
        return Err(CreatedAtTimeValidationError::InTheFuture { ledger_time: now });
    }
    Ok(())
}

pub const PENALIZE_MEMO: [u8; MAX_MEMO_LENGTH as usize] = [u8::MAX; MAX_MEMO_LENGTH as usize];
pub const CREATE_CANISTER_MEMO: [u8; MAX_MEMO_LENGTH as usize] =
    [u8::MAX - 1; MAX_MEMO_LENGTH as usize];
pub const REFUND_MEMO: [u8; MAX_MEMO_LENGTH as usize] = [u8::MAX - 2; MAX_MEMO_LENGTH as usize];

// Penalize the `from` account by burning fee tokens. Do nothing if `from`'s balance
// is lower than [crate::config::FEE].
pub fn penalize(from: &Account, now: u64) -> Option<(BlockIndex, Hash)> {
    log!(
        P1,
        "[penalize]: account {:?} is being penalized at timestamp {}",
        from,
        now
    );

    let balance = balance_of(from);

    mutate_state(|s| {
        if balance < crate::config::FEE {
            log!(
                P1,
                "[penalize]: account {:?} cannot be penalized as its balance {} is too low.",
                from,
                balance
            );
            return None;
        }

        if let Err(err) = s.debit(from, crate::config::FEE) {
            let err = err.context(format!("Unable to penalize account {:?}", from));
            ic_cdk::trap(&format!("{err:#}"))
        }
        let phash = s.last_block_hash();
        let block_hash = s.emit_block(Block {
            transaction: Transaction {
                operation: Operation::Burn {
                    from: *from,
                    spender: None,
                    amount: crate::config::FEE,
                },
                memo: Some(Memo(ByteBuf::from(PENALIZE_MEMO))),
                created_at_time: None,
            },
            timestamp: now,
            phash,
            effective_fee: Some(0),
        });
        Some((BlockIndex::from(s.blocks.len() - 1), block_hash))
    })
}

// candid::Principal has these two constants as private
const CANDID_PRINCIPAL_MAX_LENGTH_IN_BYTES: usize = 29;
const CANDID_PRINCIPAL_SELF_AUTHENTICATING_TAG: u8 = 2;

fn is_self_authenticating(principal: &Principal) -> bool {
    principal
        .as_slice()
        .get(CANDID_PRINCIPAL_MAX_LENGTH_IN_BYTES - 1)
        .is_some_and(|b| *b == CANDID_PRINCIPAL_SELF_AUTHENTICATING_TAG)
}

pub async fn withdraw(
    from: Account,
    to: Principal,
    spender: Option<Account>,
    amount: u128,
    now: u64,
    created_at_time: Option<u64>,
) -> Result<Nat, WithdrawFromError> {
    use WithdrawFromError::*;

    if is_self_authenticating(&to) {
        // if it is not an opaque principal ID, the user is trying to withdraw to a non-canister target
        return Err(InvalidReceiver { receiver: to });
    }

    if amount == 0 {
        return Err(withdraw_from::cannot_withdraw_from_zero());
    }

    let transaction = Transaction {
        operation: Operation::Burn {
            from,
            spender,
            amount,
        },
        created_at_time,
        memo: Some(encode_withdraw_memo(&to)),
    };
    check_duplicate(&transaction)?;

    // if `amount` + `fee` overflows then the user doesn't have enough funds
    let Some(amount_with_fee) = amount.checked_add(config::FEE) else {
        return Err(InsufficientFunds {
            balance: balance_of(&from).into(),
        });
    };

    // check allowance
    let mut old_expires_at = None;
    if let Some(spender) = spender {
        if spender != from {
            let (_, expiry) =
                read_state(|state| check_allowance(state, &from, &spender, amount_with_fee, now))?;
            if expiry > 0 {
                old_expires_at = Some(expiry);
            }
        }
    }

    // check that the `from` account has enough funds
    read_state(|state| state.check_debit_from_account(&from, amount_with_fee)).map_err(
        |balance| InsufficientFunds {
            balance: balance.into(),
        },
    )?;

    // sanity check that the total_supply won't underflow
    read_state(|state| state.check_total_supply_decrease(amount_with_fee))
        .with_context(|| {
            format!(
                "Unable to withdraw {} cycles from {} to {}",
                amount, from, to
            )
        })
        .map_err(withdraw_from::anyhow_error)?;

    // The withdraw process involves 3 steps:
    // 1. burn cycles + fee
    // 2. call deposit_cycles on the management canister
    // 3. if 2. fails then mint cycles

    // 1. burn cycles + fee

    let block_index = process_transaction(transaction.clone(), now)?;

    if let Some(spender) = spender {
        if spender != from {
            if let Err(err) =
                mutate_state(|state| use_allowance(state, &from, &spender, amount_with_fee, now))
            {
                let err =
                    anyhow!(err).context(format!("Unable to perform withdraw: {:?}", transaction));
                ic_cdk::trap(&format!("{err:#}"));
            };
        }
    }

    if let Err(err) = mutate_state(|state| state.debit(&from, amount_with_fee)) {
        let err = err.context(format!("Unable to perform withdraw: {:?}", transaction));
        ic_cdk::trap(&format!("{err:#}"))
    };

    prune(now);

    // 2. call deposit_cycles on the management canister
    let deposit_cycles_result = deposit_cycles(CanisterIdRecord { canister_id: to }, amount).await;
    let now = ic_cdk::api::time();

    // 3. if 2. fails then mint cycles
    if let Err((rejection_code, rejection_reason)) = deposit_cycles_result {
        // subtract the fee to pay for the reimburse block
        let amount_to_reimburse = amount.saturating_sub(config::FEE);
        if amount_to_reimburse.is_zero() {
            return Err(FailedToWithdrawFrom {
                withdraw_from_block: Some(block_index.into()),
                refund_block: None,
                approval_refund_block: None,
                rejection_code,
                rejection_reason,
            });
        }
        match reimburse(from, amount_to_reimburse, now, PENALIZE_MEMO) {
            Ok(fee_block) => {
                prune(now);
                if let Some(spender) = spender {
                    let approval_still_valid =
                        old_expires_at.map(|expiry| now < expiry).unwrap_or(true);
                    // charge FEE for every block: withdraw attempt, refund, refund approval
                    if spender != from && amount > 2 * config::FEE && approval_still_valid {
                        match reimburse_approval(
                            from,
                            spender,
                            amount_to_reimburse.saturating_sub(config::FEE),
                            old_expires_at,
                            now,
                        ) {
                            Ok(approval_refund_block) => {
                                return Err(FailedToWithdrawFrom {
                                    withdraw_from_block: Some(block_index.into()),
                                    refund_block: Some(Nat::from(fee_block)),
                                    approval_refund_block: Some(approval_refund_block),
                                    rejection_code,
                                    rejection_reason,
                                });
                            }
                            Err(err) => {
                                // this is a critical error that should not
                                // happen because approving should never fail.
                                ic_cdk::trap(&format!("Unable to reimburse approval: {:#?}", err));
                            }
                        }
                    }
                }
                return Err(FailedToWithdrawFrom {
                    withdraw_from_block: Some(block_index.into()),
                    refund_block: Some(Nat::from(fee_block)),
                    approval_refund_block: None,
                    rejection_code,
                    rejection_reason,
                });
            }
            Err(err) => {
                // this is a critical error that should not
                // happen because minting should never fail.
                ic_cdk::trap(&format!("Unable to reimburse caller: {}", err))
            }
        }
    }

    Ok(Nat::from(block_index))
}

pub async fn create_canister(
    from: Account,
    spender: Option<Account>,
    amount: u128,
    now: u64,
    created_at_time: Option<u64>,
    argument: Option<CmcCreateCanisterArgs>,
) -> Result<CreateCanisterSuccess, CreateCanisterFromError> {
    use CreateCanisterFromError::*;

    let transaction = Transaction {
        operation: Operation::Burn {
            from,
            spender,
            amount,
        },
        created_at_time,
        memo: Some(Memo::from(ByteBuf::from(CREATE_CANISTER_MEMO))),
    };
    check_duplicate(&transaction)?;

    // if `amount` + `fee` overflows then the user doesn't have enough funds
    let Some(amount_with_fee) = amount.checked_add(config::FEE) else {
        return Err(InsufficientFunds {
            balance: balance_of(&from).into(),
        });
    };

    // check allowance
    let mut old_expires_at = None;
    if let Some(spender) = spender {
        if spender != from {
            let (_, expiry) =
                read_state(|state| check_allowance(state, &from, &spender, amount_with_fee, now))?;
            if expiry > 0 {
                old_expires_at = Some(expiry);
            }
        }
    }

    // check that the `from` account has enough funds
    read_state(|state| state.check_debit_from_account(&from, amount_with_fee)).map_err(
        |balance: u128| InsufficientFunds {
            balance: balance.into(),
        },
    )?;

    // sanity check that the total_supply won't underflow
    read_state(|state| state.check_total_supply_decrease(amount_with_fee))
        .with_context(|| format!("Unable to deduct {} cycles from {}", amount, from))
        .map_err(create_canister_from::anyhow_error)?;

    // The canister creation process involves 3 steps:
    // 1. burn cycles + fee
    // 2. call create_cycles on the CMC
    // 3. if 2. fails then mint cycles

    // 1. burn cycles + fee

    let block_index = process_transaction(transaction.clone(), now)?;

    if let Some(spender) = spender {
        if spender != from {
            if let Err(err) =
                mutate_state(|state| use_allowance(state, &from, &spender, amount_with_fee, now))
            {
                let err = anyhow!(err).context(format!(
                    "unable to perform create_canister: {:?}",
                    transaction
                ));
                ic_cdk::trap(&format!("{err:#}"));
            }
        }
    }

    if let Err(err) = mutate_state(|state| state.debit(&from, amount_with_fee)) {
        let err = err.context(format!("Unable to perform create_canister {transaction}"));
        ic_cdk::trap(&format!("{err:#}"));
    };

    prune(now);

    // 2. call create_canister on the CMC

    let argument = argument
        .map(|arg| CmcCreateCanisterArgs {
            settings: arg
                .settings
                .map(|settings| CanisterSettings {
                    controllers: Some(
                        settings
                            .controllers
                            .unwrap_or_else(|| vec![ic_cdk::api::caller()]),
                    ),
                    ..settings
                })
                .or_else(|| {
                    Some(CanisterSettings {
                        controllers: Some(vec![ic_cdk::api::caller()]),
                        ..Default::default()
                    })
                }),
            ..arg
        })
        .unwrap_or_else(|| CmcCreateCanisterArgs {
            settings: Some(CanisterSettings {
                controllers: Some(vec![ic_cdk::api::caller()]),
                ..Default::default()
            }),
            subnet_selection: None,
        });
    let create_canister_result: Result<
        (Result<Principal, CmcCreateCanisterError>,),
        (RejectionCode, String),
    > = call_with_payment128(CMC_PRINCIPAL, "create_canister", (argument,), amount).await;
    let now = ic_cdk::api::time();

    // 3. if 2. fails then mint cycles

    let flat_create_canister_result = match create_canister_result {
        Ok(not_rejected) => match not_rejected {
            (Ok(success),) => Ok(success),
            (Err(err),) => match err {
                CmcCreateCanisterError::Refunded {
                    refund_amount,
                    create_error,
                } => Err((RejectionCode::CanisterError, refund_amount, create_error)),
                CmcCreateCanisterError::RefundFailed {
                    create_error,
                    refund_error,
                } => Err((
                    RejectionCode::CanisterError,
                    0,
                    format!("create_error: {create_error}, refund error: {refund_error}"),
                )),
            },
        },
        Err((rejection_code, rejection_reason)) => Err((rejection_code, amount, rejection_reason)),
    };

    match flat_create_canister_result {
        Err((rejection_code, returned_amount, rejection_reason)) => {
            // subtract the fee to pay for the reimburse block
            let amount_to_reimburse = returned_amount.saturating_sub(config::FEE);
            if amount_to_reimburse.is_zero() {
                return Err(FailedToCreateFrom {
                    create_from_block: Some(Nat::from(block_index)),
                    refund_block: None,
                    approval_refund_block: None,
                    rejection_code,
                    rejection_reason,
                });
            }
            match reimburse(from, amount_to_reimburse, now, REFUND_MEMO) {
                Ok(refund_block) => {
                    prune(now);
                    if let Some(spender) = spender {
                        let approval_still_valid =
                            old_expires_at.map(|expiry| now < expiry).unwrap_or(true);
                        // charge FEE for every block: withdraw attempt, refund, refund approval
                        if spender != from
                            && amount_to_reimburse > config::FEE
                            && approval_still_valid
                        {
                            match reimburse_approval(
                                from,
                                spender,
                                amount_to_reimburse.saturating_sub(config::FEE),
                                old_expires_at,
                                now,
                            ) {
                                Ok(approval_refund_block) => {
                                    return Err(FailedToCreateFrom {
                                        create_from_block: Some(block_index.into()),
                                        refund_block: Some(refund_block.into()),
                                        approval_refund_block: Some(approval_refund_block),
                                        rejection_code,
                                        rejection_reason,
                                    });
                                }
                                Err(err) => {
                                    // this is a critical error that should not happen because approving should never fail.
                                    ic_cdk::trap(&format!(
                                        "Unable to reimburse approval: {:#?}",
                                        err
                                    ));
                                }
                            }
                        }
                    }
                    Err(FailedToCreateFrom {
                        create_from_block: Some(block_index.into()),
                        refund_block: Some(refund_block.into()),
                        approval_refund_block: None,
                        rejection_code,
                        rejection_reason,
                    })
                }
                Err(err) => {
                    // this is a critical error that should not
                    // happen because minting should never fail.
                    ic_cdk::trap(&format!("Unable to reimburse caller: {err}"))
                }
            }
        }
        Ok(canister_id) => {
            if let Ok(tx_hash) = transaction.hash() {
                mutate_state(|state| {
                    if state.transaction_hashes.contains_key(&tx_hash) {
                        state
                            .transaction_hashes
                            .insert(tx_hash, (block_index, Some(canister_id)));
                    }
                });
            } else {
                // this should not happen because processing the transaction already checks if it can be hashed
                ic_cdk::trap(&format!("Bug: Transaction in block {block_index} was processed correctly but suddenly cannot be hashed anymore."));
            }
            Ok(CreateCanisterSuccess {
                block_id: Nat::from(block_index),
                canister_id,
            })
        }
    }
}

// Reimburse an account with a given amount
// This panics if a mint block has been recorded but the credit
// function didn't go through.
fn reimburse(
    acc: Account,
    amount: u128,
    now: u64,
    memo: [u8; MAX_MEMO_LENGTH as usize],
) -> Result<u64, ProcessTransactionError> {
    let transaction = Transaction {
        operation: Operation::Mint {
            to: acc,
            amount,
            fee: 0,
        },
        created_at_time: None,
        memo: Some(Memo::from(ByteBuf::from(memo))),
    };

    let block_index = process_transaction(transaction.clone(), now)?;

    if let Err(err) = mutate_state(|state| state.credit(&acc, amount)) {
        let err = err.context(format!("Unable to reimburse withdraw: {transaction:?}"));
        ic_cdk::trap(&format!("{err:#}"))
    };

    prune(now);

    Ok(block_index)
}

// Reimburse an approval with a given amount
fn reimburse_approval(
    from: Account,
    spender: Account,
    amount: u128,
    old_expires_at: Option<u64>,
    now: u64,
) -> Result<Nat, ApproveError> {
    let (current_allowance, current_expiry) = allowance(&from, &spender, now);
    let expires_at = if current_expiry > 0 {
        Some(current_expiry)
    } else {
        old_expires_at
    };

    approve(
        from,
        spender,
        amount.saturating_add(current_allowance),
        Some(Memo::from(ByteBuf::from(PENALIZE_MEMO))),
        now,
        None,
        None,
        None,
        expires_at,
    )
}

pub fn allowance(account: &Account, spender: &Account, now: u64) -> (u128, u64) {
    let key = (to_account_key(account), to_account_key(spender));
    let allowance = read_state(|s| s.approvals.get(&key).unwrap_or_default());
    if allowance.1 > 0 && allowance.1 < now {
        return (0, 0);
    }
    allowance
}

fn record_approval(
    s: &mut State,
    from: &Account,
    spender: &Account,
    amount: u128,
    expires_at: Option<u64>,
) {
    let key = (to_account_key(from), to_account_key(spender));

    let expires_at = expires_at.unwrap_or(0);

    match s.approvals.get(&key) {
        None => {
            if amount == 0 {
                log!(P0, "[record_approval]: amount was set to 0");
                return;
            }
            if expires_at > 0 {
                s.expiration_queue.insert((expires_at, key), ());
            }
            s.approvals.insert(key, (amount, expires_at));
        }
        Some((_, current_expiration)) => {
            if amount == 0 {
                if current_expiration > 0 {
                    s.expiration_queue.remove(&(current_expiration, key));
                }
                s.approvals.remove(&key);
                return;
            }
            s.approvals.insert(key, (amount, expires_at));
            if expires_at != current_expiration {
                if current_expiration > 0 {
                    s.expiration_queue.remove(&(current_expiration, key));
                }
                if expires_at > 0 {
                    s.expiration_queue.insert((expires_at, key), ());
                }
            }
        }
    }
}

fn check_allowance(
    s: &State,
    account: &Account,
    spender: &Account,
    amount: u128,
    now: u64,
) -> Result<(u128, u64), UseAllowanceError> {
    use UseAllowanceError::*;

    let key = (to_account_key(account), to_account_key(spender));

    if amount == 0 {
        return Err(CannotDeduceZero);
    }

    let (current_allowance, current_expiration) = s
        .approvals
        .get(&key)
        .ok_or(InsufficientAllowance { allowance: 0 })?;

    if !(current_expiration == 0 || current_expiration > now) {
        return Err(ExpiredApproval);
    }

    let new_allowance = current_allowance
        .checked_sub(amount)
        .ok_or(InsufficientAllowance {
            allowance: current_allowance,
        })?;

    Ok((new_allowance, current_expiration))
}

fn use_allowance(
    s: &mut State,
    account: &Account,
    spender: &Account,
    amount: u128,
    now: u64,
) -> Result<(), UseAllowanceError> {
    let (new_amount, expiration) = check_allowance(s, account, spender, amount, now)?;

    let key = (to_account_key(account), to_account_key(spender));

    if new_amount == 0 {
        if expiration > 0 {
            s.expiration_queue.remove(&(expiration, key));
        }
        s.approvals.remove(&key);
    } else {
        s.approvals.insert(key, (new_amount, expiration));
    }

    Ok(())
}

fn prune_approvals(now: u64, s: &mut State, limit: usize) {
    let mut pruned = 0;
    for _ in 0..limit {
        match s.expiration_queue.first_key_value() {
            None => break,
            Some((key, _)) if key.0 > now => break,
            Some((key, _value)) => {
                if s.approvals.remove(&key.1).is_none() {
                    log!(P0, "Unable to find the approval for {:?}", key.1,)
                }
                s.expiration_queue.remove(&key);
                pruned += 1;
            }
        }
    }
    if pruned > 0 {
        log!(P1, "Pruned {} approvals", pruned);
    }
}

// Returns true if the [timestamp] is before the transaction
// window. Transactions with created_at_time before the transaction
// window are eligible for pruning.
fn is_before_transaction_window(timestamp: u64, now: u64) -> bool {
    timestamp
        .saturating_add(config::TRANSACTION_WINDOW.as_nanos() as u64)
        .saturating_add(config::PERMITTED_DRIFT.as_nanos() as u64)
        < now
}

fn prune_transactions(now: u64, s: &mut State, limit: usize) {
    let mut pruned = 0;
    while let Some(((timestamp, block_idx), _)) = s.transaction_timestamps.first_key_value() {
        if pruned >= limit || !is_before_transaction_window(timestamp, now) {
            return;
        }
        s.transaction_timestamps.remove(&(timestamp, block_idx));
        pruned += 1;

        let Some(block) = s.blocks.get(block_idx) else {
            log!(
                P0,
                "Cannot find block with id: {}. The block id was associated \
                with the timestamp: {} and was selected for pruning from \
                the timestamp and hashes pools",
                block_idx,
                timestamp
            );
            continue;
        };
        let tx_hash = match block.transaction.hash() {
            Ok(tx_hash) => tx_hash,
            Err(err) => {
                log!(
                    P0,
                    "Cannot calculate hash of transaction for block id: {}. Error: {}",
                    block_idx,
                    err,
                );
                continue;
            }
        };
        match s.transaction_hashes.remove(&tx_hash) {
            None => {
                log!(P0,
                    "Transaction hash: {} for block id: {} was not found in the transaction hashes pool",
                    hex::encode(tx_hash),
                    block_idx
                );
            }
            // Transactions before and after the deduplication window never make it into storage as they are
            // rejected by the deduplication method.
            // Therefore, two tx hashes cannot exists within the deduplication window. This means that two
            // entries in the ´transaction_timestamp´ struct with the same ´created_at_timestamps´ but different
            // ´block_index´ cannot point to two blocks with identical transaction hashes within the deduplication window.
            // Example: if the ´transaction_timestamp´ storage has the entries [(time_a,block_a),(time_a,block_b)] then
            // the hashes of the transactions in block_a and block_b cannot be identical
            Some((found_block_idx, _maybe_canister)) if found_block_idx != block_idx => {
                log!(
                    P0,
                    "Block id: {} associated with the transaction hash: {} in the \
                     transaction hashes pool is different from the expected block id: {}. \
                     This is likely because there are multiple blocks with the same \
                     transaction within the transaction window.",
                    found_block_idx,
                    hex::encode(tx_hash),
                    block_idx,
                );
            }
            Some(_) => {}
        }
    }
}

pub fn get_blocks(args: GetBlocksArgs) -> GetBlocksResult {
    let log_length = read_state(|state| state.blocks.len());
    let max_length = read_state(|state| state.config.get().max_blocks_per_request);
    let mut blocks = Vec::new();
    for GetBlocksArg { start, length } in args {
        let remaining_length = max_length.saturating_sub(blocks.len() as u64);
        if remaining_length == 0 {
            break;
        }
        let start = match start.0.to_u64() {
            Some(start) if start < log_length => start,
            _ => continue,
        };
        let end_excluded = match length.0.to_u64() {
            Some(length) => log_length.min(start + remaining_length.min(length)),
            _ => continue,
        };
        read_state(|state| {
            for id in start..end_excluded {
                let block = state
                    .blocks
                    .get(id)
                    .unwrap_or_else(|| panic!("Bug: unable to find block at index {}!", id))
                    .0
                    .to_value();
                let block_with_id = BlockWithId {
                    id: Nat::from(id),
                    block,
                };
                blocks.push(block_with_id);
            }
        });
    }
    GetBlocksResult {
        log_length: Nat::from(log_length),
        blocks,
        archived_blocks: vec![],
    }
}

pub fn get_allowances(
    from: Account,
    spender: Option<Account>,
    max_results: u64,
    now: u64,
) -> Allowances {
    let mut result = vec![];
    let start_account_spender = match spender {
        Some(spender) => (to_account_key(&from), to_account_key(&spender)),
        None => (
            to_account_key(&from),
            to_account_key(&Account {
                owner: Principal::from_slice(&[0u8; 0]),
                subaccount: None,
            }),
        ),
    };
    read_state(|state| {
        for (account_spender, (allowance_amount, expiration)) in
            state.approvals.range(start_account_spender..)
        {
            if spender.is_some() && account_spender == start_account_spender {
                continue;
            }
            if result.len() >= max_results as usize {
                break;
            }
            let (from_account, to_spender) = to_account_pair(&account_spender);
            if from_account.owner != from.owner {
                break;
            }
            if expiration > 0 && expiration <= now {
                continue;
            }
            let expires_at = match expiration {
                0 => None,
                _ => Some(expiration),
            };
            result.push(Allowance {
                from_account,
                to_spender,
                allowance: Nat::from(allowance_amount),
                expires_at,
            });
        }
    });
    result
}

#[cfg(test)]
mod tests {
    use candid::Principal;
    use ic_certified_map::RbTree;
    use ic_stable_structures::{
        memory_manager::{MemoryId, MemoryManager},
        Storable, VectorMemory,
    };
    use icrc_ledger_types::{
        icrc1::{account::Account, transfer::Memo},
        icrc3,
    };
    use proptest::{
        prelude::any,
        prop_assert_eq, prop_compose, prop_oneof, proptest,
        strategy::{Just, Strategy},
    };

    use crate::{
        ciborium_to_generic_value,
        config::{self, MAX_MEMO_LENGTH},
        storage::{prune_approvals, to_account_key, Cbor, Operation, Transaction},
    };

    use super::{
        prune_transactions, Approvals, Balances, Block, BlockLog, Cache, ConfigCell,
        ExpirationQueue, State, TransactionHashes, TransactionTimeStamps,
    };

    prop_compose! {
        fn principal_strategy()
                             (bytes in any::<[u8; 29]>())
                             -> Principal {
            Principal::from_slice(&bytes)
        }
    }

    prop_compose! {
        fn account_strategy()
                           (owner in principal_strategy(),
                            subaccount in proptest::option::of(any::<[u8; 32]>()))
                            -> Account {
            Account { owner, subaccount }
        }
    }

    prop_compose! {
        fn approve_strategy()
                           (from in account_strategy(),
                            spender in account_strategy(),
                            amount in any::<u128>(),
                            expected_allowance in proptest::option::of(any::<u128>()),
                            expires_at in proptest::option::of(any::<u64>()),
                            fee in proptest::option::of(any::<u128>()))
                           -> Operation {
            Operation::Approve { from, spender, amount, expected_allowance, expires_at, fee }
        }
    }

    prop_compose! {
        fn burn_strategy()
                        (from in account_strategy(),
                             spender in proptest::option::of(account_strategy()),
                             amount in any::<u128>())
                        -> Operation {
            Operation::Burn { from, spender, amount }
        }
    }

    prop_compose! {
        fn mint_strategy()
                        (to in account_strategy(),
                         amount in any::<u128>(),
                         fee in prop_oneof![Just(0), Just(config::FEE)])
                        -> Operation {
            Operation::Mint { to, amount, fee }
        }
    }

    prop_compose! {
        fn transfer_strategy()
                            (from in account_strategy(),
                             to in account_strategy(),
                             spender in proptest::option::of(account_strategy()),
                             amount in any::<u128>(),
                             fee in proptest::option::of(any::<u128>()))
                            -> Operation {
            Operation::Transfer { from, to, spender, amount, fee }
        }
    }

    fn operation_strategy() -> impl Strategy<Value = Operation> {
        prop_oneof![
            approve_strategy(),
            burn_strategy(),
            mint_strategy(),
            transfer_strategy()
        ]
    }

    prop_compose! {
        fn memo_strategy()
                        (bytes in any::<[u8; MAX_MEMO_LENGTH as usize]>())
                        -> Memo {
            Memo::from(bytes.to_vec())
        }
    }

    prop_compose! {
        fn transaction_strategy()
                               (operation in operation_strategy(),
                                created_at_time in proptest::option::of(any::<u64>()),
                                memo in proptest::option::of(memo_strategy()))
                               -> Transaction {
            Transaction { operation, created_at_time, memo }
        }
    }

    prop_compose! {
        // Generate a block with no parent hash set
        fn block_strategy()
                         (transaction in transaction_strategy(),
                          timestamp in any::<u64>(),
                          phash in proptest::option::of(any::<[u8;32]>()),
                          effective_fee in proptest::option::of(any::<u128>()))
                         -> Block {
            Block { transaction, timestamp, phash, effective_fee}
        }
    }

    // Use proptest to generate blocks and call
    // cbor(block).to_bytes()/from_bytes(), to_value and
    // hash on them.
    // The test succeeds if hash never panics, which means
    // that `Block::to_value` is always safe to call.
    #[test]
    fn test_block_ser_to_value_and_hash() {
        let test_conf = proptest::test_runner::Config {
            // Increase the cases so that more blocks are tested.
            // 2048 cases take around 0.89s to run.
            cases: 2048,
            // Fail as soon as one test fails, all blocks should
            // pass the test
            max_local_rejects: 1,
            max_shrink_iters: 0,
            ..Default::default()
        };
        proptest!(test_conf, |(block in block_strategy())| {
            let cblock = Cbor(block.clone());
            let actual_block = Cbor::<Block>::from_bytes(cblock.to_bytes());
            prop_assert_eq!(&block, &actual_block.0, "{:?}", block);

            let value = block.clone().to_value();
            let actual_block = Block::from_value(value)
                .expect("Unable to convert value to block");
            prop_assert_eq!(&block, &actual_block, "{:?}", block);
            prop_assert_eq!(block.clone().hash(), actual_block.hash(), "{:?}", block);
            // check the "old" hash without the FI-1247 fix
            let old_value = ciborium::Value::serialized(&block).unwrap_or_else(|e| panic!(
                "Bug: unable to convert Block to Ciborium Value.\nBlock: {:?}: {e:?}",
                block
            ));
            let old_value = ciborium_to_generic_value(&old_value, 0).unwrap_or_else(|e| panic!(
                "Bug: unable to convert Ciborium Value to Value.\nBlock: {:?}\nValue: {:?}: {e:?}",
                block, old_value
            ));
            prop_assert_eq!(block.hash(), old_value.hash());
        });
    }

    #[test]
    fn test_block_schema() {
        let test_conf = proptest::test_runner::Config {
            // Increase the cases so that more blocks are tested.
            // 2048 cases take around 0.89s to run.
            cases: 2048,
            // Fail as soon as one test fails, all blocks should
            // pass the test
            max_local_rejects: 1,
            max_shrink_iters: 0,
            ..Default::default()
        };
        proptest!(test_conf, |(block in block_strategy())| {
            let value = block.to_value();
            if let Err(err) = icrc3::schema::validate(&value) {
                panic!("block {} is not a valid icrc3 block. Errors:\n{}", value, err)
            }
        });
    }

    #[test]
    fn test_prune_approvals() {
        let test_conf = proptest::test_runner::Config {
            // creating the state is quite slow and therefore
            // we limit the test cases to 1 with no shrinking
            cases: 1,
            max_shrink_iters: 0,
            ..Default::default()
        };
        let from_spenders_strategy: Vec<_> = (0..10)
            .map(|_| (account_strategy(), account_strategy()))
            .collect();
        proptest!(test_conf, move |(from_spenders in from_spenders_strategy)| {
            let mut state = new_test_state();
            let curr = 2;
            let expired = 1;

            // 6 expired approvals to be pruned and 4 not
            for (block_idx, (from, spender)) in from_spenders.iter().enumerate() {
                let from_key = to_account_key(from);
                let spender_key = to_account_key(spender);
                let key = (from_key, spender_key);
                state.approvals.insert(key, (1, block_idx as u64));
                let expires_at = if block_idx < 6 { expired } else { curr };
                state.expiration_queue.insert((expires_at, key), ());
            }

            // prune no approvals if now == 0
            prune_approvals(expired - 1, &mut state, usize::MAX);
            prop_assert_eq!(state.approvals.len(), from_spenders.len() as u64);
            prop_assert_eq!(state.expiration_queue.len(), from_spenders.len() as u64);

            // prune only 2 approvals if now == expired but limit == 2
            prune_approvals(expired, &mut state, 2);
            prop_assert_eq!(state.approvals.len() + 2, from_spenders.len() as u64);
            prop_assert_eq!(state.expiration_queue.len() + 2, from_spenders.len() as u64);

            // prune only 4 approvals if now == expired
            prune_approvals(expired, &mut state, usize::MAX);
            prop_assert_eq!(state.approvals.len() + 6, from_spenders.len() as u64);
            prop_assert_eq!(state.expiration_queue.len() + 6, from_spenders.len() as u64);

            // do not prune anything else because the last 4 approvals have created_at_time == curr
            prune_approvals(expired, &mut state, usize::MAX);
            prop_assert_eq!(state.approvals.len() + 6, from_spenders.len() as u64);
            prop_assert_eq!(state.expiration_queue.len() + 6, from_spenders.len() as u64);
        })
    }

    #[test]
    fn test_prune_transaction() {
        let test_conf = proptest::test_runner::Config {
            // creating the state is quite slow and therefore
            // we limit the test cases to 1 with no shrinking
            cases: 1,
            max_shrink_iters: 0,
            ..Default::default()
        };
        let blocks_strategy: Vec<_> = (0..10).map(|_| block_strategy()).collect();
        proptest!(test_conf, move |(mut blocks in blocks_strategy)| {
            let mut state = new_test_state();
            let window_plus_drift = config::TRANSACTION_WINDOW.as_nanos() as u64 +
                                    config::PERMITTED_DRIFT.as_nanos() as u64;
            let curr = 3 * window_plus_drift;
            let old = 0;

            // set the phash to create a real chain
            for i in 1..blocks.len() {
                blocks[i].phash = Some(blocks[i-1].clone().hash())
            }

            for (i, block) in blocks.iter_mut().enumerate() {
                // set created_at_time for deduplication
                // the fist 6 blocks are old and will be pruned, the last 4 are in the tx window
                block.transaction.created_at_time = Some(if i < 6 { old } else { curr });
                state.blocks.append(&crate::storage::Cbor(block.clone())).unwrap();
                state.transaction_hashes.insert(block.transaction.hash().unwrap(), (i as u64, None));
                if let Some(created_at_time) = block.transaction.created_at_time {
                    state.transaction_timestamps.insert((created_at_time, i as u64), ());
                }
            }

            // prune no transaction if now == old
            prune_transactions(old, &mut state, usize::MAX);
            prop_assert_eq!(state.blocks.len(), blocks.len() as u64);
            prop_assert_eq!(state.transaction_hashes.len(), blocks.len() as u64);
            prop_assert_eq!(state.transaction_timestamps.len(), blocks.len() as u64);

            // prune only 2 txs if now == curr but limit == 2
            prune_transactions(curr, &mut state, 2);
            prop_assert_eq!(state.blocks.len(), blocks.len() as u64);
            prop_assert_eq!(state.transaction_hashes.len() + 2, blocks.len() as u64);
            prop_assert_eq!(state.transaction_timestamps.len() + 2, blocks.len() as u64);

            // prune only 4 txs if now == curr
            prune_transactions(curr, &mut state, usize::MAX);
            prop_assert_eq!(state.blocks.len(), blocks.len() as u64);
            prop_assert_eq!(state.transaction_hashes.len() + 6, blocks.len() as u64);
            prop_assert_eq!(state.transaction_timestamps.len() + 6, blocks.len() as u64);

            // do not prune anything else because the last 4 txs have created_at_time == curr
            prune_transactions(curr, &mut state, usize::MAX);
            prop_assert_eq!(state.blocks.len(), blocks.len() as u64);
            prop_assert_eq!(state.transaction_hashes.len() + 6, blocks.len() as u64);
            prop_assert_eq!(state.transaction_timestamps.len() + 6, blocks.len() as u64);
        })
    }

    fn new_test_state() -> State {
        let memory_manager = MemoryManager::init(VectorMemory::default());
        let block_log_index_memory = memory_manager.get(MemoryId::new(1));
        let block_log_data_memory = memory_manager.get(MemoryId::new(2));
        let balances_memory = memory_manager.get(MemoryId::new(3));
        let approvals_memory = memory_manager.get(MemoryId::new(4));
        let expiration_queue_memory = memory_manager.get(MemoryId::new(5));
        let transaction_hashes_memory = memory_manager.get(MemoryId::new(6));
        let transaction_timestamps_memory = memory_manager.get(MemoryId::new(7));
        let config_memory = memory_manager.get(MemoryId::new(8));
        State {
            blocks: BlockLog::new(block_log_index_memory, block_log_data_memory),
            balances: Balances::new(balances_memory),
            approvals: Approvals::new(approvals_memory),
            expiration_queue: ExpirationQueue::new(expiration_queue_memory),
            transaction_hashes: TransactionHashes::new(transaction_hashes_memory),
            transaction_timestamps: TransactionTimeStamps::new(transaction_timestamps_memory),
            config: ConfigCell::new(config_memory, crate::config::Config::default()).unwrap(),
            cache: Cache {
                phash: None,
                total_supply: 0,
                hash_tree: RbTree::default(),
            },
        }
    }

    #[test]
    fn test_u64_to_leb128() {
        for i in [0, 1, u64::MAX - 1, u64::MAX] {
            let mut buf = Vec::with_capacity(crate::storage::MAX_U64_ENCODING_BYTES);
            leb128::write::unsigned(&mut buf, i).unwrap();
            let decoded = leb128::read::unsigned(&mut buf.as_slice()).unwrap();
            assert_eq!(i, decoded);
        }
    }
}

mod phash {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_bytes::ByteBuf;

    pub fn serialize<S>(phash: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match phash {
            None => serializer.serialize_none(),
            Some(phash) => serializer.serialize_some(&ByteBuf::from(phash.as_slice())),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<ByteBuf>::deserialize(deserializer)? {
            None => Ok(None),
            Some(bb) => match <[u8; 32]>::try_from(bb.as_slice()) {
                Ok(phash) => Ok(Some(phash)),
                Err(err) => Err(D::Error::custom(err)),
            },
        }
    }
}

#[test]
fn test_phash_serialization_roundtrip() {
    use proptest::prelude::any;
    use proptest::proptest;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(transparent)]
    struct Wrap(#[serde(with = "phash")] Option<[u8; 32]>);

    fn test_phash(phash: Option<[u8; 32]>) {
        let wrap = Wrap(phash);
        let value = ciborium::Value::serialized(&wrap).expect("Unable to serialize phash");
        if phash.is_none() {
            assert!(value.is_null());
        } else {
            assert!(value.is_bytes());
        }
    }

    proptest!(|(phash in proptest::option::of(any::<[u8; 32]>()))| {
        test_phash(phash)
    })
}
