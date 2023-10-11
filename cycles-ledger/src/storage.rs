use crate::config::Config;
use crate::endpoints::{DataCertificate, SendError};
use crate::logs::{P0, P1};
use crate::{
    ciborium_to_generic_value, compact_account,
    config::{self, MAX_MEMO_LENGTH},
    endpoints::{
        GetTransactionsArg, GetTransactionsArgs, GetTransactionsResult, TransactionWithId,
    },
    generic_to_ciborium_value,
};
use anyhow::Context;
use candid::Nat;
use ic_canister_log::log;
use ic_cdk::api::set_certified_data;
use ic_certified_map::{AsHashTree, RbTree};
use ic_stable_structures::{
    cell::Cell as StableCell,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Blob,
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
};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::borrow::Cow;
use std::cell::RefCell;

const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);
const BALANCES_MEMORY_ID: MemoryId = MemoryId::new(3);
const APPROVALS_MEMORY_ID: MemoryId = MemoryId::new(4);
const EXPIRATION_QUEUE_MEMORY_ID: MemoryId = MemoryId::new(5);
const TRANSACTION_HASH_MEMORY_ID: MemoryId = MemoryId::new(6);
const TRANSACTION_TIMESTAMP_MEMORY_ID: MemoryId = MemoryId::new(7);
const CONFIG_MEMORY_ID: MemoryId = MemoryId::new(8);

type VMem = VirtualMemory<DefaultMemoryImpl>;

pub type AccountKey = (Blob<29>, [u8; 32]);
pub type BlockLog = StableLog<Cbor<Block>, VMem, VMem>;
pub type Balances = StableBTreeMap<AccountKey, u128, VMem>;
pub type TransactionHashes = StableBTreeMap<Hash, u64, VMem>;
pub type TransactionTimeStampKey = (u64, u64);
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
pub struct Transaction {
    pub operation: Operation,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ts")]
    pub created_at_time: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<Memo>,
}

impl Transaction {
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Operation {
    Mint {
        #[serde(with = "compact_account")]
        to: Account,
        #[serde(rename = "amt")]
        amount: u128,
    },
    Transfer {
        #[serde(with = "compact_account")]
        from: Account,
        #[serde(with = "compact_account")]
        to: Account,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "compact_account::opt"
        )]
        spender: Option<Account>,
        #[serde(rename = "amt")]
        amount: u128,
        #[serde(skip_serializing_if = "Option::is_none")]
        fee: Option<u128>,
    },
    Burn {
        #[serde(with = "compact_account")]
        from: Account,
        #[serde(rename = "amt")]
        amount: u128,
    },
    Approve {
        #[serde(with = "compact_account")]
        from: Account,
        #[serde(with = "compact_account")]
        spender: Account,
        #[serde(rename = "amt")]
        amount: u128,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_allowance: Option<u128>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expires_at: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fee: Option<u128>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Block {
    pub transaction: Transaction,
    #[serde(rename = "ts")]
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phash: Option<[u8; 32]>,
    #[serde(rename = "fee")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_fee: Option<u128>,
}

impl Block {
    pub fn from_value(value: Value) -> anyhow::Result<Self> {
        let value = generic_to_ciborium_value(&value, 0).context(format!(
            "Bug: unable to convert Value to Ciborium Value. Value: {:?}",
            value
        ))?;
        ciborium::value::Value::deserialized(&value).context(format!(
            "Bug: unable to convert Ciborium Value to Block. Value: {:?}",
            value
        ))
    }

    pub fn to_value(&self) -> anyhow::Result<Value> {
        let value = ciborium::Value::serialized(self).context(format!(
            "Bug: unable to convert Block to Ciborium Value. Block: {:?}",
            self
        ))?;
        ciborium_to_generic_value(&value, 0).context(format!(
            "Bug: unable to convert Ciborium Value to Value. Block: {:?}, Value: {:?}",
            self, value
        ))
    }

    /// Panics if [to_value] fails.
    pub fn hash(&self) -> anyhow::Result<Hash> {
        self.to_value()
            .map(|v| v.hash())
            .context("Bug: Unable to calculate block hash")
    }
}

pub struct State {
    pub blocks: BlockLog,
    balances: Balances,
    pub approvals: Approvals,
    pub expiration_queue: ExpirationQueue,
    pub transaction_hashes: TransactionHashes,
    pub transaction_timestamps: TransactionTimeStamps,
    pub config: ConfigCell,
    // In-memory cache dropped on each upgrade.
    cache: Cache,
}

impl State {
    pub fn last_block_hash(&self) -> Option<Hash> {
        self.cache.phash
    }

    pub fn total_supply(&self) -> u128 {
        self.cache.total_supply
    }

    /// Increases the balance of an account of the given amount.
    /// Panics if there is an overflow or the new balance cannot be inserted.
    pub fn credit(&mut self, account: &Account, amount: u128) -> u128 {
        let account_key = to_account_key(account);
        let old_balance = self.balances.get(&account_key).unwrap_or_default();
        let new_balance = old_balance
            .checked_add(amount)
            .expect("Overflow while changing the account balance");
        self.balances.insert(account_key, new_balance);
        self.cache.total_supply = self
            .total_supply()
            .checked_add(amount)
            .expect("Overflow while changing the total supply");
        new_balance
    }

    /// Decreases the balance of an account of the given amount.
    /// Panics if there is an overflow or the new balance cannot be inserted.
    pub fn debit(&mut self, account: &Account, amount: u128) -> u128 {
        let account_key = to_account_key(account);
        let old_balance = self.balances.get(&account_key).unwrap_or_default();
        let new_balance = old_balance
            .checked_sub(amount)
            .expect("Underflow while changing the account balance");
        if new_balance == 0 {
            self.balances.remove(&account_key);
        } else {
            self.balances.insert(account_key, new_balance);
        }
        self.cache.total_supply = self
            .total_supply()
            .checked_sub(amount)
            .expect("Underflow while changing the total supply");
        new_balance
    }

    pub fn get_tip_certificate(&self) -> Option<DataCertificate> {
        let certificate = match ic_cdk::api::data_certificate() {
            Some(certificate) => ByteBuf::from(certificate),
            None => return None,
        };
        let hash_tree = ByteBuf::from(
            serde_cbor::to_vec(
                &self
                    .cache
                    .hash_tree
                    .value_range(b"last_block_hash", b"last_block_index"),
            )
            .expect(
                "Bug: unable to write last_block_hash and last_block_index values in the hash_tree",
            ),
        );
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
        let last_block_hash = blocks.get(n - 1).unwrap().hash().unwrap();
        populate_last_block_hash_and_hash_tree(&mut hash_tree, n - 1, last_block_hash);
        (Some(last_block_hash), hash_tree)
    }

    pub fn emit_block(&mut self, b: Block) -> Hash {
        let hash = b.hash().unwrap();
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
                .insert(tx_hash, self.blocks.len() - 1);
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

pub fn populate_last_block_hash_and_hash_tree(
    hash_tree: &mut RbTree<&'static str, Vec<u8>>,
    last_block_index: u64,
    last_block_hash: Hash,
) {
    hash_tree.insert("last_block_index", last_block_index.to_be_bytes().to_vec());
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
}

pub fn to_account_key(account: &Account) -> AccountKey {
    (
        Blob::try_from(account.owner.as_slice())
            .expect("principals cannot be longer than 29 bytes"),
        *account.effective_subaccount(),
    )
}

pub fn balance_of(account: &Account) -> u128 {
    read_state(|s| s.balances.get(&to_account_key(account)).unwrap_or_default())
}

pub fn record_deposit(
    account: &Account,
    amount: u128,
    memo: Option<Memo>,
    now: u64,
) -> (u64, u128, Hash) {
    mutate_state(|s| {
        let new_balance = s.credit(account, amount);
        let phash = s.last_block_hash();
        let block_hash = s.emit_block(Block {
            transaction: Transaction {
                operation: Operation::Mint {
                    to: *account,
                    amount,
                },
                memo,
                created_at_time: None,
            },
            timestamp: now,
            phash,
            effective_fee: Some(0),
        });
        (s.blocks.len() - 1, new_balance, block_hash)
    })
}

pub enum CreatedAtTimeValidation {
    TooOld,
    InTheFuture { ledger_time: u64 },
}

impl From<CreatedAtTimeValidation> for TransferFromError {
    fn from(value: CreatedAtTimeValidation) -> Self {
        match value {
            CreatedAtTimeValidation::TooOld => Self::TooOld,
            CreatedAtTimeValidation::InTheFuture { ledger_time } => {
                Self::CreatedInFuture { ledger_time }
            }
        }
    }
}

impl From<CreatedAtTimeValidation> for SendError {
    fn from(value: CreatedAtTimeValidation) -> Self {
        match value {
            CreatedAtTimeValidation::TooOld => Self::TooOld,
            CreatedAtTimeValidation::InTheFuture { ledger_time } => {
                Self::CreatedInFuture { ledger_time }
            }
        }
    }
}

impl From<CreatedAtTimeValidation> for ApproveError {
    fn from(value: CreatedAtTimeValidation) -> Self {
        match value {
            CreatedAtTimeValidation::TooOld => Self::TooOld,
            CreatedAtTimeValidation::InTheFuture { ledger_time } => {
                Self::CreatedInFuture { ledger_time }
            }
        }
    }
}

pub fn validate_created_at_time(
    created_at_time: &Option<u64>,
    now: u64,
) -> Result<(), CreatedAtTimeValidation> {
    let Some(created_at_time) = created_at_time else { return Ok(())};
    if created_at_time
        .saturating_add(config::TRANSACTION_WINDOW.as_nanos() as u64)
        .saturating_add(config::PERMITTED_DRIFT.as_nanos() as u64)
        < now
    {
        return Err(CreatedAtTimeValidation::TooOld);
    }

    if created_at_time > &now.saturating_add(config::PERMITTED_DRIFT.as_nanos() as u64) {
        return Err(CreatedAtTimeValidation::InTheFuture { ledger_time: now });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn transfer(
    from: &Account,
    to: &Account,
    spender: Option<Account>,
    amount: u128,
    memo: Option<Memo>,
    now: u64,
    created_at_time: Option<u64>,
    suggested_fee: Option<u128>,
) -> (u64, Hash) {
    let total_spent_amount = amount.saturating_add(crate::config::FEE);

    mutate_state(|s| {
        if let Some(spender) = spender {
            if spender != *from {
                use_allowance(s, from, &spender, total_spent_amount, now);
            }
        }

        s.debit(from, total_spent_amount);
        s.credit(to, amount);

        let phash = s.last_block_hash();
        let block_hash = s.emit_block(Block {
            transaction: Transaction {
                operation: Operation::Transfer {
                    from: *from,
                    to: *to,
                    spender,
                    amount,
                    fee: suggested_fee,
                },
                memo,
                created_at_time,
            },
            timestamp: now,
            phash,
            effective_fee: suggested_fee.is_none().then_some(config::FEE),
        });
        (s.blocks.len() - 1, block_hash)
    })
}

const PENALIZE_MEMO: [u8; MAX_MEMO_LENGTH as usize] = [u8::MAX; MAX_MEMO_LENGTH as usize];

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

        s.debit(from, crate::config::FEE);
        let phash = s.last_block_hash();
        let block_hash = s.emit_block(Block {
            transaction: Transaction {
                operation: Operation::Burn {
                    from: *from,
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

pub fn send(
    from: &Account,
    amount: u128,
    memo: Option<Memo>,
    now: u64,
    created_at_time: Option<u64>,
) -> (BlockIndex, Hash) {
    mutate_state(|s| {
        let total_balance_deduction = amount.saturating_add(crate::config::FEE);

        s.debit(from, total_balance_deduction);
        let phash = s.last_block_hash();
        let block_hash = s.emit_block(Block {
            transaction: Transaction {
                operation: Operation::Burn {
                    from: *from,
                    amount,
                },
                memo,
                created_at_time,
            },
            timestamp: now,
            phash,
            effective_fee: Some(crate::config::FEE),
        });
        (BlockIndex::from(s.blocks.len() - 1), block_hash)
    })
}

pub fn allowance(account: &Account, spender: &Account, now: u64) -> (u128, u64) {
    let key = (to_account_key(account), to_account_key(spender));
    let allowance = read_state(|s| s.approvals.get(&key).unwrap_or_default());
    if allowance.1 > 0 && allowance.1 < now {
        return (0, 0);
    }
    allowance
}

#[allow(clippy::too_many_arguments)]
pub fn approve(
    from_spender: (&Account, &Account),
    amount: u128,
    expires_at: Option<u64>,
    now: u64,
    expected_allowance: Option<u128>,
    memo: Option<Memo>,
    created_at_time: Option<u64>,
    suggested_fee: Option<u128>,
) -> u64 {
    let from = from_spender.0;
    let spender = from_spender.1;

    mutate_state(|s| {
        record_approval(s, from, spender, amount, expires_at);

        s.debit(from, crate::config::FEE);

        let phash = s.last_block_hash();
        s.emit_block(Block {
            transaction: Transaction {
                operation: Operation::Approve {
                    from: *from,
                    spender: *spender,
                    amount,
                    expected_allowance,
                    expires_at,
                    fee: suggested_fee,
                },
                memo,
                created_at_time,
            },
            timestamp: now,
            phash,
            effective_fee: suggested_fee.is_none().then_some(config::FEE),
        });
        s.blocks.len() - 1
    })
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

fn use_allowance(s: &mut State, account: &Account, spender: &Account, amount: u128, now: u64) {
    let key = (to_account_key(account), to_account_key(spender));

    if amount == 0 {
        ic_cdk::trap("Cannot deduct amount 0 from allowance")
    }
    let (current_allowance, current_expiration) = s.approvals.get(&key).unwrap_or_else(|| {
        ic_cdk::trap(&format!(
            "Allowance does not exist, account {}, spender {}",
            account, spender
        ));
    });

    if !(current_expiration == 0 || current_expiration > now) {
        ic_cdk::trap(&format!(
            "Expired allowance, expiration {} is earlier than now {}",
            current_expiration, now
        ))
    }

    if current_allowance < amount {
        ic_cdk::trap(&format!(
            "Insufficient allowance, current_allowance {}, total spent amount {}",
            current_allowance, amount
        ))
    }

    let new_amount = current_allowance - amount;
    if new_amount == 0 {
        if current_expiration > 0 {
            s.expiration_queue.remove(&(current_expiration, key));
        }
        s.approvals.remove(&key);
    } else {
        s.approvals.insert(key, (new_amount, current_expiration));
    }
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
            log!(P0,
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
            Some(found_block_idx) if found_block_idx != block_idx => {
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

pub fn get_transactions(args: GetTransactionsArgs) -> GetTransactionsResult {
    let log_length = read_state(|state| state.blocks.len());
    let max_length = read_state(|state| state.config.get().max_transactions_per_request);
    let mut transactions = Vec::new();
    for GetTransactionsArg { start, length } in args {
        let remaining_length = max_length.saturating_sub(transactions.len() as u64);
        if remaining_length == 0 {
            break;
        }
        let start = match start.0.to_u64() {
            Some(start) if start < log_length => start,
            _ => continue, // TODO(FI-924): log this error
        };
        let end_excluded = match length.0.to_u64() {
            Some(length) => log_length.min(start + remaining_length.min(length)),
            None => continue, // TODO(FI-924): log this error
        };
        read_state(|state| {
            for id in start..end_excluded {
                let transaction = state
                    .blocks
                    .get(id)
                    .unwrap_or_else(|| panic!("Bug: unable to find block at index {}!", id))
                    .0
                    .to_value()
                    .unwrap_or_else(|e| panic!("Error on block at index {}: {}", id, e));
                let transaction_with_id = TransactionWithId {
                    id: Nat::from(id),
                    transaction,
                };
                transactions.push(transaction_with_id);
            }
        });
    }
    GetTransactionsResult {
        log_length: Nat::from(log_length),
        transactions,
        archived_transactions: vec![],
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use candid::Principal;
    use ic_certified_map::RbTree;
    use ic_stable_structures::{
        memory_manager::{MemoryId, MemoryManager},
        VectorMemory,
    };
    use icrc_ledger_types::{
        icrc::generic_value::Value,
        icrc1::{account::Account, transfer::Memo},
    };
    use num_bigint::BigUint;
    use proptest::{
        prelude::any, prop_assert, prop_assert_eq, prop_compose, prop_oneof, proptest,
        strategy::Strategy,
    };

    use crate::{
        ciborium_to_generic_value,
        config::{self, MAX_MEMO_LENGTH},
        storage::{prune_approvals, to_account_key, Operation, Transaction},
    };

    use super::{
        prune_transactions, Approvals, Balances, Block, BlockLog, Cache, ConfigCell,
        ExpirationQueue, State, TransactionHashes, TransactionTimeStamps,
    };

    #[test]
    fn test_u128_encoding() {
        // ciborium_to_generic_value should convert u128 to Value::Nat
        let num = u128::MAX; // u128::MAX is 340282366920938463463374607431768211455
        let expected = Value::Nat(candid::Nat(
            BigUint::from_str("340282366920938463463374607431768211455").unwrap(),
        ));

        let cvalue = ciborium::Value::serialized(&num).unwrap();
        let value = ciborium_to_generic_value(&cvalue, 0).unwrap();

        assert_eq!(value, expected);
    }

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
                         amount in any::<u128>())
                        -> Operation {
            Operation::Burn { from, amount }
        }
    }

    prop_compose! {
        fn mint_strategy()
                        (to in account_strategy(),
                         amount in any::<u128>())
                        -> Operation {
            Operation::Mint { to, amount }
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
                          effective_fee in proptest::option::of(any::<u128>()))
                         -> Block {
            Block { transaction, timestamp, phash: None, effective_fee}
        }
    }

    // Use proptest to genereate blocks and call hash on them.
    // The test succeeeds if hash never panics, which means
    // that `Block::to_value` is always safe to call.
    #[test]
    fn test_block_to_value_and_hash() {
        let test_conf = proptest::test_runner::Config {
            // Increase the cases so that more blocks are tested.
            // 2048 cases take around 0.89s to run.
            cases: 2048,
            ..Default::default()
        };
        proptest!(test_conf, |(block in block_strategy())| {
            let value = block.to_value()
                .expect("Unable to convert value to block");
            let actual_block = Block::from_value(value)
                .expect("Unable to convert value to block");
            prop_assert_eq!(&block, &actual_block);
            prop_assert!(block.hash().is_ok())
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
                blocks[i].phash = Some(blocks[i-1].hash().unwrap())
            }

            for (i, block) in blocks.iter_mut().enumerate() {
                // set created_at_time for deduplication
                // the fist 6 blocks are old and will be pruned, the last 4 are in the tx window
                block.transaction.created_at_time = Some(if i < 6 { old } else { curr });
                state.blocks.append(&crate::storage::Cbor(block.clone())).unwrap();
                state.transaction_hashes.insert(block.transaction.hash().unwrap(), i as u64);
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
}
