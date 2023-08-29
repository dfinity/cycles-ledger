use crate::generic_to_ciborium_value;
use crate::{
    ciborium_to_generic_value, compact_account,
    config::{self, MAX_MEMO_LENGTH},
    endpoints::DeduplicationError,
};
use anyhow::Context;
use candid::Nat;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Blob,
    DefaultMemoryImpl, StableBTreeMap, StableLog, Storable,
};
use icrc_ledger_types::{
    icrc::generic_value::Value,
    icrc1::{
        account::Account,
        transfer::{BlockIndex, Memo},
    },
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::borrow::Cow;
use std::cell::RefCell;

const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);
const BALANCES_MEMORY_ID: MemoryId = MemoryId::new(3);
const APPROVALS_MEMORY_ID: MemoryId = MemoryId::new(4);
const EXPIRATION_QUEUE_MEMORY_ID: MemoryId = MemoryId::new(5);
const TRANSACTION_MEMORY_ID: MemoryId = MemoryId::new(6);

type VMem = VirtualMemory<DefaultMemoryImpl>;

pub type AccountKey = (Blob<29>, [u8; 32]);
pub type BlockLog = StableLog<Cbor<Block>, VMem, VMem>;
pub type Balances = StableBTreeMap<AccountKey, u128, VMem>;
pub type TransactionLog = StableBTreeMap<Hash, u64, VMem>;

pub type ApprovalKey = (AccountKey, AccountKey);
pub type Approvals = StableBTreeMap<ApprovalKey, (u128, u64), VMem>;
pub type ExpirationQueue = StableBTreeMap<(u64, ApprovalKey), (), VMem>;

pub type Hash = [u8; 32];

pub struct Cache {
    // The hash of the last block.
    pub phash: Option<Hash>,
    // The total supply of cycles.
    pub total_supply: u128,
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
    pub fn hash(&self) -> Hash {
        let value = ciborium::Value::serialized(self).unwrap_or_else(|e| {
            panic!(
                "Bug: unable to convert Operation to Ciborium Value. Error: {}, Block: {:?}",
                e, self
            )
        });
        match ciborium_to_generic_value(&value.clone(), 0) {
            Ok(value) => value.hash(),
            Err(err) =>
                panic!("Bug: unable to convert Ciborium Value to Value. Error: {}, Block: {:?}, Value: {:?}", err, self, value),
        }
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
    transaction: Transaction,
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

    pub fn hash(&self) -> Hash {
        match self.to_value() {
            Ok(value) => value.hash(),
            Err(err) => panic!("{}", err),
        }
    }
}

pub struct State {
    pub blocks: BlockLog,
    balances: Balances,
    pub approvals: Approvals,
    pub expiration_queue: ExpirationQueue,
    pub transactions: TransactionLog,
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
    pub fn credit(&mut self, account_key: AccountKey, amount: u128) -> u128 {
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
    pub fn debit(&mut self, account_key: AccountKey, amount: u128) -> u128 {
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

    pub fn emit_block(&mut self, b: Block) -> Hash {
        let hash = b.hash();
        self.cache.phash = Some(hash);
        let tx_hash = b.transaction.hash();
        self.blocks
            .append(&Cbor(b))
            .expect("failed to append a block");
        // Add block index to the list of transactions and set the hash as its key
        self.transactions.insert(tx_hash, self.blocks.len() - 1);
        hash
    }

    fn compute_last_block_hash(blocks: &BlockLog) -> Option<Hash> {
        let n = blocks.len();
        if n == 0 {
            return None;
        }
        let last_block = blocks.get(n - 1).unwrap();
        Some(last_block.hash())
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

        RefCell::new(State {
            cache: Cache {
                phash: State::compute_last_block_hash(&blocks),
                total_supply: State::compute_total_supply(&balances),
            },
            blocks,
            balances,
            approvals: Approvals::init(mm.get(APPROVALS_MEMORY_ID)),
            transactions: TransactionLog::init(mm.get(TRANSACTION_MEMORY_ID)),
            expiration_queue: ExpirationQueue::init(mm.get(EXPIRATION_QUEUE_MEMORY_ID)),
        })
    });
}

pub fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|cell| f(&cell.borrow()))
}

const APPROVE_PRUNE_LIMIT: usize = 100;

pub fn mutate_state<R>(now: u64, f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|cell| {
        let result = f(&mut cell.borrow_mut());
        prune(&mut cell.borrow_mut(), now, APPROVE_PRUNE_LIMIT);
        check_invariants(&cell.borrow());
        result
    })
}

fn check_invariants(s: &State) {
    if s.expiration_queue.len() > s.approvals.len() {
        ic_cdk::trap(&format!(
            "expiration_queue len ({}) larger than approvals len ({})",
            s.expiration_queue.len(),
            s.approvals.len()
        ))
    }
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
    if amount < crate::config::FEE {
        ic_cdk::trap(&format!(
            "The requested amount {} to be deposited is less than the cycles ledger fee: {}",
            amount,
            crate::config::FEE
        ))
    }

    let key = to_account_key(account);
    mutate_state(now, |s| {
        let new_balance = s.credit(key, amount);
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
            effective_fee: Some(crate::config::FEE),
        });
        (s.blocks.len() - 1, new_balance, block_hash)
    })
}

// This method implements deduplication accorind to the ICRC-1 standard: https://github.com/dfinity/ICRC-1
pub fn deduplicate(
    created_at_timestamp: Option<u64>,
    tx_hash: [u8; 32],
    now: u64,
) -> Result<(), DeduplicationError> {
    // TODO: purge old transactions
    if let (Some(created_at_time), tx_hash) = (created_at_timestamp, tx_hash) {
        // If the created timestamp is outside of the permitted Transaction window
        if created_at_time
            .saturating_add(config::TRANSACTION_WINDOW.as_nanos() as u64)
            .saturating_add(config::PERMITTED_DRIFT.as_nanos() as u64)
            < now
        {
            return Err(DeduplicationError::TooOld);
        }

        if created_at_time > now.saturating_add(config::PERMITTED_DRIFT.as_nanos() as u64) {
            return Err(DeduplicationError::CreatedInFuture { ledger_time: now });
        }

        if let Some(block_height) = read_state(|state| state.transactions.get(&tx_hash)) {
            return Err(DeduplicationError::Duplicate {
                duplicate_of: Nat::from(block_height),
            });
        }
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
    let from_key = to_account_key(from);
    let to_key = to_account_key(to);
    let total_spent_amount = amount.saturating_add(crate::config::FEE);
    let from_balance = read_state(|s| s.balances.get(&from_key).unwrap_or_default());
    check_transfer_preconditions(from_balance, total_spent_amount, now, created_at_time);

    mutate_state(now, |s| {
        if let Some(spender) = spender {
            if spender != *from {
                use_allowance(s, from, &spender, total_spent_amount, now);
            }
        }

        s.debit(from_key, total_spent_amount);
        s.credit(to_key, amount);

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

fn check_transfer_preconditions(
    from_balance: u128,
    total_spent_amount: u128,
    now: u64,
    created_at_time: Option<u64>,
) {
    if from_balance < total_spent_amount {
        ic_cdk::trap(&format!("The balance of the account sending cycles {} is lower than the total amount of cycles needed to make the transfer {}",from_balance,total_spent_amount))
    }
    if let Some(time) = created_at_time {
        if time > now.saturating_add(crate::config::PERMITTED_DRIFT.as_nanos() as u64) {
            ic_cdk::trap(&format!(
                "Transfer created in the future, created_at_time: {}, now: {}",
                time, now
            ))
        }
    }
}

const PENALIZE_MEMO: [u8; MAX_MEMO_LENGTH as usize] = [u8::MAX; MAX_MEMO_LENGTH as usize];

// Penalize the `from` account by burning fee tokens. Do nothing if `from`'s balance
// is lower than [crate::config::FEE].
pub fn penalize(from: &Account, now: u64) -> Option<(BlockIndex, Hash)> {
    let from_key = to_account_key(from);

    mutate_state(now, |s| {
        let balance = s.balances.get(&from_key).unwrap_or_default();
        if balance < crate::config::FEE {
            return None;
        }

        s.debit(from_key, crate::config::FEE);
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
    let from_key = to_account_key(from);

    mutate_state(now, |s| {
        let from_balance = s.balances.get(&from_key).unwrap_or_default();
        let total_balance_deduction = amount.saturating_add(crate::config::FEE);

        if from_balance < total_balance_deduction {
            ic_cdk::trap(&format!("The balance of the account sending cycles {} is lower than the total amount of cycles needed to make the transfer {}",from_balance,total_balance_deduction))
        }

        s.debit(from_key, total_balance_deduction);
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
            effective_fee: Some(0),
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
    let from_key = to_account_key(from);
    let from_balance = read_state(|s| s.balances.get(&from_key).unwrap_or_default());

    check_approve_preconditions(
        from,
        from_balance,
        spender,
        expires_at,
        now,
        created_at_time,
    );

    mutate_state(now, |s| {
        record_approval(s, from, spender, amount, expires_at, expected_allowance);

        s.debit(from_key, crate::config::FEE);

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

fn check_approve_preconditions(
    from: &Account,
    from_balance: u128,
    spender: &Account,
    expires_at: Option<u64>,
    now: u64,
    created_at_time: Option<u64>,
) {
    if from_balance < crate::config::FEE {
        ic_cdk::trap(&format!(
            "The balance of the account {:?} is {} which is lower than the cycles ledger fee {}",
            from,
            from_balance,
            crate::config::FEE
        ))
    }
    if from == spender {
        ic_cdk::trap("self approvals are not allowed, should be checked in the endpoint")
    }
    if expires_at.unwrap_or(REMOTE_FUTURE) <= now {
        ic_cdk::trap(&format!(
            "Approval expiration time ({}) should be later than now ({now})",
            expires_at.unwrap_or(REMOTE_FUTURE)
        ))
    }
    if let Some(time) = created_at_time {
        if time > now.saturating_add(crate::config::PERMITTED_DRIFT.as_nanos() as u64) {
            ic_cdk::trap(&format!(
                "Approval created in the future, created_at_time: {}, now: {}",
                time, now
            ))
        }
    }
}

const REMOTE_FUTURE: u64 = u64::MAX;

fn record_approval(
    s: &mut State,
    from: &Account,
    spender: &Account,
    amount: u128,
    expires_at: Option<u64>,
    expected_allowance: Option<u128>,
) {
    let key = (to_account_key(from), to_account_key(spender));

    let expires_at = expires_at.unwrap_or(0);

    match s.approvals.get(&key) {
        None => {
            if let Some(expected_allowance) = expected_allowance {
                assert_eq!(expected_allowance, 0);
            }
            if amount == 0 {
                return;
            }
            if expires_at > 0 {
                s.expiration_queue.insert((expires_at, key), ());
            }
            s.approvals.insert(key, (amount, expires_at));
        }
        Some((current_allowance, current_expiration)) => {
            if let Some(expected_allowance) = expected_allowance {
                assert_eq!(expected_allowance, current_allowance);
            }
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
        ic_cdk::trap("Cannot use amount 0 from allowance")
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

fn prune(s: &mut State, now: u64, limit: usize) -> usize {
    let mut pruned = 0;

    for _ in 0..limit {
        match s.expiration_queue.first_key_value() {
            Some((key, _value)) => {
                if key.0 > now {
                    return pruned;
                }
                s.approvals.remove(&key.1);
                s.expiration_queue.remove(&key);
                pruned += 1;
            }
            None => {
                return pruned;
            }
        }
    }
    pruned
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use candid::Principal;
    use icrc_ledger_types::{
        icrc::generic_value::Value,
        icrc1::{account::Account, transfer::Memo},
    };
    use num_bigint::BigUint;
    use proptest::{prelude::any, prop_compose, prop_oneof, proptest, strategy::Strategy};

    use crate::{
        ciborium_to_generic_value,
        config::MAX_MEMO_LENGTH,
        storage::{Operation, Transaction},
    };

    use super::Block;

    #[test]
    fn test_block_hash() {
        let block = Block {
            transaction: Transaction {
                operation: Operation::Transfer {
                    from: Account::from(Principal::anonymous()),
                    to: Account::from(Principal::anonymous()),
                    spender: None,
                    amount: u128::MAX,
                    fee: Some(10_000),
                },
                memo: Some(Memo::default()),
                created_at_time: None,
            },
            timestamp: 1691065957,
            phash: None,
            effective_fee: None,
        };
        // check that it doesn't panic and that it doesn't return a fake hash
        assert_ne!(block.hash(), [0u8; 32]);
    }

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

    proptest! {

        #[test]
        fn test_block_to_value(block in block_strategy()) {
            let value = block.to_value()
                .expect("Unable to convert block to value");
            let actual_block = Block::from_value(value)
                .expect("Unable to convert value to block");
            assert_eq!(block, actual_block)
        }
    }
}
