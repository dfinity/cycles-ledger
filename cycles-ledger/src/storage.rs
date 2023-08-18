use candid::Nat;
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

use crate::{ciborium_to_generic_value, compact_account, config, endpoints::DeduplicationError};

const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);
const BALANCES_MEMORY_ID: MemoryId = MemoryId::new(3);
const TRANSACTIONS_MEMORY_ID: MemoryId = MemoryId::new(4);

type VMem = VirtualMemory<DefaultMemoryImpl>;

pub type AccountKey = (Blob<29>, [u8; 32]);
pub type BlockLog = StableLog<Cbor<Block>, VMem, VMem>;
pub type Balances = StableBTreeMap<AccountKey, u128, VMem>;
pub type TransactionsLog = StableBTreeMap<Hash, u64, VMem>;

pub type Hash = [u8; 32];

pub struct Cache {
    // The hash of the last block.
    pub phash: Option<Hash>,
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

impl Transaction {
    pub fn hash(&self) -> Hash {
        let value = ciborium::Value::serialized(self).unwrap_or_else(|e| {
            panic!(
                "Bug: unable to convert Operation to Ciborium Value. Error: {}, Block: {:?}",
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Operation {
    Mint {
        #[serde(with = "compact_account")]
        to: Account,
        #[serde(rename = "amt")]
        amount: u128,
        fee: u128,
    },
    Transfer {
        #[serde(with = "compact_account")]
        from: Account,
        #[serde(with = "compact_account")]
        to: Account,
        #[serde(rename = "amt")]
        amount: u128,
        fee: u128,
    },
    Burn {
        #[serde(with = "compact_account")]
        from: Account,
        #[serde(rename = "amt")]
        amount: u128,
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
    pub balances: Balances,
    pub transactions: TransactionsLog,
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
            transactions: TransactionsLog::init(mm.get(TRANSACTIONS_MEMORY_ID)),
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
    created_at_time: Option<u64>,
) -> (u64, u128, Hash) {
    assert!(amount >= crate::config::FEE);

    let key = to_account_key(account);
    mutate_state(|s| {
        let balance = s.balances.get(&key).unwrap_or_default();
        let new_balance = balance + amount;
        s.balances.insert(key, new_balance);
        let phash = s.last_block_hash();
        let block_hash = s.emit_block(Block {
            transaction: Transaction {
                operation: Operation::Mint {
                    to: *account,
                    amount,
                    fee: crate::config::FEE,
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

pub fn deduplicate(
    created_at_timestamp: Option<u64>,
    tx_hash: [u8; 32],
    now: u64,
) -> Result<(), DeduplicationError> {
    // TODO: purge old transactions
    if let (Some(created_at_time), tx_hash) = (created_at_timestamp, tx_hash) {
        // If the created timestamp is outside of the permitted Transaction window
        if created_at_time
            + (config::TRANSACTION_WINDOW.as_nanos() as u64)
            + (config::PERMITTED_DRIFT.as_nanos() as u64)
            < now
        {
            return Err(DeduplicationError::TooOld);
        }

        if created_at_time > now + (config::PERMITTED_DRIFT.as_nanos() as u64) {
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

pub fn transfer(
    from: Account,
    to: Account,
    amount: u128,
    fee: u128,
    created_at_time: Option<u64>,
    memo: Option<Memo>,
    now: u64,
) -> (u64, Hash) {
    let from_key = to_account_key(&from);
    let to_key = to_account_key(&to);

    mutate_state(|s| {
        let from_balance = s.balances.get(&from_key).unwrap_or_default();

        assert!(from_balance >= amount.saturating_add(crate::config::FEE));
        assert!(fee == crate::config::FEE);

        s.balances
            .insert(
                from_key,
                from_balance - amount.saturating_add(crate::config::FEE),
            )
            .expect("failed to update 'from' balance");

        let to_balance = s.balances.get(&to_key).unwrap_or_default();
        s.balances.insert(to_key, to_balance + amount);

        let phash = s.last_block_hash();
        let block_hash = s.emit_block(Block {
            transaction: Transaction {
                operation: Operation::Transfer {
                    from,
                    to,
                    amount,
                    fee,
                },
                created_at_time,
                memo,
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
            transaction: Transaction {
                operation: Operation::Burn {
                    from: *from,
                    amount: 0,
                    fee: crate::config::FEE,
                },
                memo: None,
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
            transaction: Transaction {
                operation: Operation::Burn {
                    from: *from,
                    amount,
                    fee: crate::config::FEE,
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
