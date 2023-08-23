use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Blob,
    DefaultMemoryImpl, StableBTreeMap, StableLog, Storable,
};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{BlockIndex, Memo},
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::borrow::Cow;
use std::cell::RefCell;

use crate::{ciborium_to_generic_value, compact_account, config::MAX_MEMO_LENGTH};

const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);
const BALANCES_MEMORY_ID: MemoryId = MemoryId::new(3);
const APPROVALS_MEMORY_ID: MemoryId = MemoryId::new(4);
const EXPIRATION_QUEUE_MEMORY_ID: MemoryId = MemoryId::new(5);

type VMem = VirtualMemory<DefaultMemoryImpl>;

pub type AccountKey = (Blob<29>, [u8; 32]);
pub type BlockLog = StableLog<Cbor<Block>, VMem, VMem>;
pub type Balances = StableBTreeMap<AccountKey, u128, VMem>;

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

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Serialize, Deserialize, Clone, Debug)]
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
        fee: u128,
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
        fee: u128,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Block {
    transaction: Transaction,
    #[serde(rename = "ts")]
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phash: Option<[u8; 32]>,
}

impl Block {
    pub fn hash(&self) -> Hash {
        let value = ciborium::Value::serialized(self).unwrap_or_else(|e| {
            panic!(
                "Bug: unable to convert Block to Ciborium Value. Error: {}, Block: {:?}",
                e, self
            )
        });
        match ciborium_to_generic_value(value.clone(), 0) {
            Ok(value) => value.hash(),
            Err(err) =>
                panic!("Bug: unable to convert Ciborium Value to Value. Error: {}, Block: {:?}, Value: {:?}", err, self, value),
        }
    }
}

pub struct State {
    pub blocks: BlockLog,
    balances: Balances,
    pub approvals: Approvals,
    pub expiration_queue: ExpirationQueue,
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
        self.blocks
            .append(&Cbor(b))
            .expect("failed to append a block");
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
    debug_assert!(
        s.expiration_queue.len() <= s.approvals.len(),
        "expiration_queue len ({}) larger than approvals len ({})",
        s.expiration_queue.len(),
        s.approvals.len()
    );
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
    created_at_time: Option<u64>,
) -> (u64, u128, Hash) {
    assert!(amount >= crate::config::FEE);

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
                created_at_time,
            },
            timestamp: now,
            phash,
        });
        (s.blocks.len() - 1, new_balance, block_hash)
    })
}

pub fn transfer(
    from: &Account,
    to: &Account,
    spender: Option<Account>,
    amount: u128,
    memo: Option<Memo>,
    now: u64,
    created_at_time: Option<u64>,
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
                    fee: crate::config::FEE,
                },
                memo,
                created_at_time,
            },
            timestamp: now,
            phash,
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
    assert!(from_balance >= total_spent_amount);
    if let Some(time) = created_at_time {
        assert!(
            time <= now.saturating_add(crate::config::PERMITTED_DRIFT.as_nanos() as u64),
            "Transfer created in the future, created_at_time: {}, now: {}",
            time,
            now
        );
    }
}

const PENALIZE_MEMO: [u8; MAX_MEMO_LENGTH as usize] = [u8::MAX; MAX_MEMO_LENGTH as usize];

pub fn penalize(from: &Account, now: u64) -> (BlockIndex, Hash) {
    let from_key = to_account_key(from);

    mutate_state(now, |s| {
        let amount = s
            .balances
            .get(&from_key)
            .unwrap_or_default()
            .min(crate::config::FEE);
        s.debit(from_key, amount);
        let phash = s.last_block_hash();
        let block_hash = s.emit_block(Block {
            transaction: Transaction {
                operation: Operation::Burn {
                    from: *from,
                    amount,
                },
                memo: Some(Memo(ByteBuf::from(PENALIZE_MEMO))),
                created_at_time: None,
            },
            timestamp: now,
            phash,
        });
        (BlockIndex::from(s.blocks.len() - 1), block_hash)
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

        assert!(from_balance >= total_balance_deduction);

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

pub fn approve(
    from_spender: (&Account, &Account),
    amount: u128,
    expires_at: Option<u64>,
    now: u64,
    expected_allowance: Option<u128>,
    memo: Option<Memo>,
    created_at_time: Option<u64>,
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
                    fee: crate::config::FEE,
                },
                memo,
                created_at_time,
            },
            timestamp: now,
            phash,
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
    assert!(from_balance >= crate::config::FEE);
    assert!(
        from != spender,
        "self approvals are not allowed, should be checked in the endpoint"
    );
    assert!(
        expires_at.unwrap_or(REMOTE_FUTURE) > now,
        "Approval expiration time ({}) should be later than now ({now})",
        expires_at.unwrap_or(REMOTE_FUTURE),
    );
    if let Some(time) = created_at_time {
        assert!(
            time <= now.saturating_add(crate::config::PERMITTED_DRIFT.as_nanos() as u64),
            "Approval created in the future, created_at_time: {time}, now: {now}"
        );
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

    assert!(amount > 0, "Cannot use amount 0 from allowance");
    let (current_allowance, current_expiration) = s.approvals.get(&key).unwrap_or_else(|| {
        panic!(
            "Allowance does not exist, account {}, spender {}",
            account, spender
        )
    });
    assert!(
        current_expiration == 0 || current_expiration > now,
        "Expired allowance, expiration {} is earlier than now {}",
        current_expiration,
        now
    );
    assert!(
        current_allowance >= amount,
        "Insufficient allowance, current_allowance {}, total spent amount {}",
        current_allowance,
        amount
    );

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

    use crate::{
        ciborium_to_generic_value,
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
                    fee: 10_000,
                },
                memo: Some(Memo::default()),
                created_at_time: None,
            },
            timestamp: 1691065957,
            phash: None,
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
        let value = ciborium_to_generic_value(cvalue, 0).unwrap();

        assert_eq!(value, expected);
    }
}
