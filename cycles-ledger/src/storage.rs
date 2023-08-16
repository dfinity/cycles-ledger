use candid::Nat;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Blob,
    DefaultMemoryImpl, StableBTreeMap, StableLog, Storable,
};
use icrc_ledger_types::{
    icrc1::{
        account::Account,
        transfer::{BlockIndex, Memo},
    },
    icrc2::approve::ApproveError,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;

use crate::{ciborium_to_generic_value, compact_account, GenericTransferError};

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
        fee: u128,
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
        fee: u128,
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
    pub balances: Balances,
    pub approvals: Approvals,
    pub expiration_queue: ExpirationQueue,
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
            approvals: Approvals::init(mm.get(APPROVALS_MEMORY_ID)),
            expiration_queue: ExpirationQueue::init(mm.get(EXPIRATION_QUEUE_MEMORY_ID)),
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

pub fn transfer(
    from: &Account,
    to: &Account,
    spender: Option<Account>,
    amount: u128,
    memo: Option<Memo>,
    now: u64,
    created_at_time: Option<u64>,
) -> Result<(u64, Hash), GenericTransferError> {
    let from_key = to_account_key(from);
    let to_key = to_account_key(to);

    let total_spent_amount = amount.saturating_add(crate::config::FEE);
    let from_balance = read_state(|s| s.balances.get(&from_key).unwrap_or_default());
    assert!(from_balance >= total_spent_amount);

    if spender.is_some() && spender.unwrap() != *from {
        use_allowance(from, &spender.unwrap(), total_spent_amount, now)?;
    }

    mutate_state(|s| {
        s.balances
            .insert(from_key, from_balance - total_spent_amount)
            .expect("failed to update 'from' balance");

        let to_balance = s.balances.get(&to_key).unwrap_or_default();
        s.balances.insert(to_key, to_balance + amount);

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
        Ok((s.blocks.len() - 1, block_hash))
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

pub fn allowance(account: &Account, spender: &Account, now: u64) -> (u128, u64) {
    let key = (to_account_key(account), to_account_key(spender));
    let allowance = read_state(|s| s.approvals.get(&key).unwrap_or_default());
    if allowance.1 > 0 {
        if allowance.1 > now {
            return allowance;
        } else {
            return (0, 0);
        }
    }
    allowance
}

pub fn approve(
    from: &Account,
    spender: &Account,
    amount: u128,
    expires_at: Option<u64>,
    now: u64,
    expected_allowance: Option<u128>,
    memo: Option<Memo>,
    created_at_time: Option<u64>,
) -> Result<u64, ApproveError> {
    let from_key = to_account_key(from);
    let from_balance = read_state(|s| s.balances.get(&from_key).unwrap_or_default());
    assert!(from_balance >= crate::config::FEE);

    record_approval(from, spender, amount, expires_at, now, expected_allowance)?;

    mutate_state(|s| {
        s.balances
            .insert(from_key, from_balance - crate::config::FEE)
            .expect("failed to update 'from' balance");

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
        Ok(s.blocks.len() - 1)
    })
}

const APPROVE_PRUNE_LIMIT: usize = 100;
const REMOTE_FUTURE: u64 = u64::MAX;

fn record_approval(
    from: &Account,
    spender: &Account,
    amount: u128,
    expires_at: Option<u64>,
    now: u64,
    expected_allowance: Option<u128>,
) -> Result<(), ApproveError> {
    prune(now, APPROVE_PRUNE_LIMIT);

    debug_assert!(
        from != spender,
        "self approvals are not allowed, should be checked in the endpoint"
    );

    if expires_at.unwrap_or(REMOTE_FUTURE) <= now {
        return Err(ApproveError::Expired { ledger_time: now });
    }

    let key = (to_account_key(from), to_account_key(spender));

    let expires_at = match expires_at {
        Some(expires_at) => expires_at,
        None => 0,
    };

    mutate_state(|s| match s.approvals.get(&key) {
        None => {
            if amount == 0 {
                return Ok(());
            }
            if let Some(expected_allowance) = expected_allowance {
                if expected_allowance != 0 {
                    return Err(ApproveError::AllowanceChanged {
                        current_allowance: Nat::from(0),
                    });
                }
            }
            if expires_at > 0 {
                s.expiration_queue.insert((expires_at, key), ());
            }
            s.approvals.insert(key, (amount, expires_at));
            Ok(())
        }
        Some(allowance) => {
            if let Some(expected_allowance) = expected_allowance {
                if expected_allowance != allowance.0 {
                    return Err(ApproveError::AllowanceChanged {
                        current_allowance: Nat::from(allowance.0),
                    });
                }
            }
            if amount == 0 {
                if allowance.1 > 0 {
                    s.expiration_queue.remove(&(allowance.1, key));
                }
                s.approvals.remove(&key);
                return Ok(());
            }
            s.approvals.insert(key, (amount, expires_at));
            if expires_at != allowance.1 {
                if allowance.1 > 0 {
                    s.expiration_queue.remove(&(allowance.1, key));
                }
                if expires_at > 0 {
                    s.expiration_queue.insert((expires_at, key), ());
                }
            }
            Ok(())
        }
    })
}

fn use_allowance(
    account: &Account,
    spender: &Account,
    amount: u128,
    now: u64,
) -> Result<(), GenericTransferError> {
    let key = (to_account_key(account), to_account_key(spender));

    mutate_state(|s| match s.approvals.get(&key) {
        None => Err(GenericTransferError::InsufficientAllowance { allowance: 0 }),
        Some(allowance) => {
            if allowance.1 != 0 && allowance.1 <= now {
                Err(GenericTransferError::InsufficientAllowance { allowance: 0 })
            } else {
                if allowance.0 < amount {
                    return Err(GenericTransferError::InsufficientAllowance {
                        allowance: allowance.0,
                    });
                }
                let new_amount = allowance
                    .0
                    .checked_sub(amount)
                    .expect("Underflow when using allowance");
                if new_amount == 0 {
                    if allowance.1 > 0 {
                        s.expiration_queue.remove(&(allowance.1, key));
                    }
                    s.approvals.remove(&key);
                } else {
                    s.approvals.insert(key, (new_amount, allowance.1));
                }
                Ok(())
            }
        }
    })
}

fn prune(now: u64, limit: usize) -> usize {
    let mut pruned = 0;
    mutate_state(|s| {
        for _ in 0..limit {
            match s.expiration_queue.first_key_value() {
                Some((key, _value)) => {
                    if key.0 > now {
                        return;
                    }
                }
                None => {
                    return;
                }
            }
            if let Some((key, _value)) = s.expiration_queue.first_key_value() {
                if key.0 <= now {
                    s.approvals.remove(&key.1);
                    s.expiration_queue.remove(&key);
                    pruned += 1;
                }
            }
        }
        debug_assert!(
            s.expiration_queue.len() <= s.approvals.len(),
            "expiration_queue len ({}) larger than approvals len ({})",
            s.expiration_queue.len(),
            s.approvals.len()
        );
    });
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
