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
use std::borrow::Cow;
use std::cell::RefCell;

const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);
const BALANCES_MEMORY_ID: MemoryId = MemoryId::new(3);

type VMem = VirtualMemory<DefaultMemoryImpl>;

pub type AccountKey = (Blob<29>, [u8; 32]);
pub type BlockLog = StableLog<Cbor<Block>, VMem, VMem>;
pub type Balances = StableBTreeMap<AccountKey, u128, VMem>;

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
    },
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

pub fn penalize(from: &Account, now: u64) -> (BlockIndex, Hash) {
    let from_key = to_account_key(from);

    mutate_state(|s| {
        let balance = s.balances.get(&from_key).unwrap_or_default();

        if crate::config::FEE >= balance {
            s.balances.remove(&from_key);
        } else {
            s.balances
                .insert(from_key, balance.saturating_sub(crate::config::FEE))
                .expect("failed to update balance");
        }
        let phash = s.last_block_hash();
        let block_hash = s.emit_block(Block {
            op: Operation::Burn {
                from: *from,
                amount: 0,
                memo: None,
                fee: crate::config::FEE,
            },
            timestamp: now,
            phash,
        });
        (BlockIndex::from(s.blocks.len() - 1), block_hash)
    })
}

pub fn send(from: &Account, amount: u128, memo: Option<Memo>, now: u64) -> (BlockIndex, Hash) {
    let from_key = to_account_key(from);

    mutate_state(|s| {
        let from_balance = s.balances.get(&from_key).unwrap_or_default();
        let total_balance_deduction = amount.saturating_add(crate::config::FEE);

        assert!(from_balance >= total_balance_deduction);

        s.balances
            .insert(
                from_key,
                from_balance.saturating_sub(total_balance_deduction),
            )
            .expect("failed to update balance");
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
        (BlockIndex::from(s.blocks.len() - 1), block_hash)
    })
}
