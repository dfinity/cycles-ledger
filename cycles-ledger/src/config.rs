use candid::{CandidType, Deserialize, Principal};
use ic_stable_structures::Storable;
use serde::Serialize;
use std::{borrow::Cow, time::Duration};

pub const FEE: u128 = 100_000_000;
pub const DECIMALS: u8 = 0;
pub const TOKEN_NAME: &str = "Cycles";
pub const TOKEN_SYMBOL: &str = "CYCLES";
pub const MAX_MEMO_LENGTH: u64 = 32;
pub const PERMITTED_DRIFT: Duration = Duration::from_secs(60);
pub const TRANSACTION_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
// The maximum number of transactions in the transaction-to-hash and block-timestamp-to-block-index mappings to be pruned in a single prune process
pub const TRANSACTION_PRUNE_LIMIT: usize = 100_000;
// The maximum number of entries in the approval list and expiration queue to be pruned in a single prune process
pub const APPROVE_PRUNE_LIMIT: usize = 100;
pub const REMOTE_FUTURE: u64 = u64::MAX;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Config {
    /// The maximum number of transactions
    /// returned by the [icrc3_get_transactions]
    /// endpoint
    pub max_transactions_per_request: u64,

    /// The principal of the index canister
    /// for this ledger
    pub index_id: Option<Principal>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_transactions_per_request: 1000,
            index_id: None,
        }
    }
}

impl Storable for Config {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut bytes = vec![];
        ciborium::into_writer(self, &mut bytes).expect("Unable to serialize the config as CBOR");
        Cow::Owned(bytes)
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        ciborium::from_reader::<Self, _>(bytes.as_ref())
            .expect("Unable to deserialize the config from its CBOR form")
    }

    const BOUND: ic_stable_structures::storable::Bound =
        ic_stable_structures::storable::Bound::Unbounded;
}

#[test]
fn test_config_ser_de() {
    // do not use default
    let config = Config {
        max_transactions_per_request: 10,
        index_id: None,
    };
    assert_eq!(Config::from_bytes(config.to_bytes()), config);
}
