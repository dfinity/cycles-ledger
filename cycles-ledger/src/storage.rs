use crate::{endpoints::Memo, Account};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Blob,
    DefaultMemoryImpl, StableBTreeMap, StableLog, Storable,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::BTreeMap};
use std::cell::RefCell;

const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);
const BALANCES_MEMORY_ID: MemoryId = MemoryId::new(3);

type VMem = VirtualMemory<DefaultMemoryImpl>;

pub type AccountKey = (Blob<29>, [u8; 32]);
pub type BlockLog = StableLog<Cbor<Block>, VMem, VMem>;
pub type Balances = StableBTreeMap<AccountKey, u128, VMem>;
pub type ReservedBalances = BTreeMap<AccountKey, u128>;

pub type Hash = [u8; 32];

pub struct Cache {
    // The hash of the last block.
    pub phash: Option<Hash>,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Operation {
    Mint {
        #[serde(rename = "to")]
        to: Account,
        #[serde(rename = "amt")]
        amount: u128,
        #[serde(rename = "fee")]
        fee: u128,
        #[serde(rename = "memo")]
        #[serde(skip_serializing_if = "Option::is_none")]
        memo: Option<Memo>,
    },
    Transfer {
        #[serde(rename = "from")]
        from: Account,
        #[serde(rename = "to")]
        to: Account,
        #[serde(rename = "amt")]
        amount: u128,
        #[serde(rename = "fee")]
        fee: u128,
        #[serde(rename = "memo")]
        #[serde(skip_serializing_if = "Option::is_none")]
        memo: Option<Memo>,
    },
    Burn {
        #[serde(rename = "from")]
        from: Account,
        #[serde(rename = "amt")]
        amount: u128,
        #[serde(rename = "fee")]
        fee: u128,
        #[serde(rename = "memo")]
        #[serde(skip_serializing_if = "Option::is_none")]
        memo: Option<Memo>,
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Block {
    #[serde(rename = "op")]
    op: Operation,
    #[serde(rename = "ts")]
    pub timestamp: u64,
    #[serde(rename = "phash")]
    pub phash: Option<[u8; 32]>,
}

impl Block {
    pub fn hash(&self) -> Hash {
        // FIXME
        [0; 32]
    }
}

pub struct State {
    pub blocks: BlockLog,
    pub balances: Balances,
    pub reserved_balances: ReservedBalances,
    // In-memory cache dropped on each upgrade.
    pub cache: Cache,
}

impl State {
    pub fn last_block_hash(&self) -> Option<Hash> {
        self.cache.phash
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

        RefCell::new(State {
            cache: Cache {
                phash: State::compute_last_block_hash(&blocks),
            },
            blocks,
            balances: Balances::init(mm.get(BALANCES_MEMORY_ID)),
            reserved_balances: ReservedBalances::default(),
        })
    });
}

pub fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|cell| f(&cell.borrow()))
}

pub fn mutate_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|cell| f(&mut cell.borrow_mut()))
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

fn to_account_key(account: &Account) -> AccountKey {
    (
        Blob::try_from(account.owner.as_slice())
            .expect("principals cannot be longer than 29 bytes"),
        *account.effective_subaccount(),
    )
}

pub fn balance_of(account: &Account) -> u128 {
    read_state(|s| s.balances.get(&to_account_key(account)).unwrap_or_default())
}

pub fn available_balance_of(account: &Account) -> u128 {
    read_state(|s| {
        let account_key = to_account_key(account);
        s.balances.get(&account_key).map(|balance| balance - s.reserved_balances.get(&account_key).unwrap_or(&0)).unwrap_or_default()
    })
}

pub fn reserve_balance(account: &Account, amount: u128) -> Result<(), ()> {
    if available_balance_of(account) > amount {
        let account_key = to_account_key(account);
        mutate_state(|s| {
            let reserved_balance = s.reserved_balances.entry(account_key).or_default();
            *reserved_balance += amount;
        });
        Ok(())
    } else {
        Err(())
    }
}

pub fn release_balance(account: &Account, amount: u128) {
    mutate_state(|s| {
        let account_key = to_account_key(account);
        if let Some(reserved) = s.reserved_balances.get_mut(&account_key) {
            if *reserved > amount {
                *reserved -= amount;
            } else {
                let _ = s.reserved_balances.remove(&account_key);
            }
        }
    })
}

pub fn record_deposit(
    account: &Account,
    amount: u128,
    memo: Option<Memo>,
    now: u64,
) -> (u64, u128, Hash) {
    assert!(amount >= crate::config::FEE);

    let key = to_account_key(account);
    mutate_state(|s| {
        let balance = s.balances.get(&key).unwrap_or_default();
        let new_balance = balance + amount;
        s.balances.insert(key, new_balance);
        let phash = s.last_block_hash();
        let block_hash = s.emit_block(Block {
            op: Operation::Mint {
                to: *account,
                amount,
                memo,
                fee: crate::config::FEE,
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
    amount: u128,
    memo: Option<Memo>,
    now: u64,
) -> (u64, Hash) {
    let from_key = to_account_key(from);
    let to_key = to_account_key(to);

    mutate_state(|s| {
        let from_balance = s.balances.get(&from_key).unwrap_or_default();

        assert!(from_balance >= amount.saturating_add(crate::config::FEE));

        s.balances
            .insert(
                from_key,
                from_balance - amount.saturating_add(crate::config::FEE),
            )
            .expect("failed to update 'from' balance");

        let to_balance = s.balances.get(&to_key).unwrap_or_default();
        s.balances
            .insert(to_key, to_balance + amount)
            .expect("failed to update 'to' balance");

        let phash = s.last_block_hash();
        let block_hash = s.emit_block(Block {
            op: Operation::Transfer {
                from: *from,
                to: *to,
                amount,
                memo,
                fee: crate::config::FEE,
            },
            timestamp: now,
            phash,
        });
        (s.blocks.len() - 1, block_hash)
    })
}

pub fn burn(
    from: &Account,
    amount: u128,
    memo: Option<Memo>,
    now: u64
) -> (u64, Hash) {
    let from_key = to_account_key(from);

    mutate_state(|s| {
        let from_balance = s.balances.get(&from_key).unwrap_or_default();

        assert!(from_balance >= amount.saturating_add(crate::config::FEE));

        s.balances
            .insert(
                from_key,
                from_balance - amount.saturating_add(crate::config::FEE),
            )
            .expect("failed to update 'from' balance");
        let phash = s.last_block_hash();
        let block_hash = s.emit_block(Block {
            op: Operation::Burn {
                from: *from,
                amount,
                memo,
                fee: crate::config::FEE,
            },
            timestamp: now,
            phash,
        });
        (s.blocks.len() - 1, block_hash)
    })
}
