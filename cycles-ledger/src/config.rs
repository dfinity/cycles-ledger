use candid::{CandidType, Deserialize, Principal};
use ic_stable_structures::Storable;
use icrc_ledger_types::icrc1::account::Account;
use serde::Serialize;
use std::{borrow::Cow, time::Duration};

pub const FEE: u128 = 100_000_000;
pub const DECIMALS: u8 = 12;
pub const TOKEN_NAME: &str = "Trillion Cycles";
pub const TOKEN_SYMBOL: &str = "TCYCLES";
// URI encoding of the file `/assets/Cycles_Icon.svg`
pub const TOKEN_LOGO: &str = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjgzIiBoZWlnaHQ9IjI4NCIgdmlld0JveD0iMCAwIDI4MyAyODQiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxwYXRoIGQ9Ik0yODAuNDM2IDE0Mi4wNDRDMjgwLjQzNiA2NS4zMTMxIDIxOC4yMzMgMy4xMTAzNSAxNDEuNTAyIDMuMTEwMzVDNjQuNzcwNyAzLjExMDM1IDIuNTY3ODcgNjUuMzEzMSAyLjU2Nzg3IDE0Mi4wNDRDMi41Njc4NyAyMTguNzc1IDY0Ljc3MDcgMjgwLjk3OCAxNDEuNTAyIDI4MC45NzhDMjE4LjIzMyAyODAuOTc4IDI4MC40MzYgMjE4Ljc3NSAyODAuNDM2IDE0Mi4wNDRaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBvcGFjaXR5PSIwLjIiIGQ9Ik0xNDEuNTAxIDI1NC45NTVDMjAzLjg2IDI1NC45NTUgMjU0LjQxMiAyMDQuNDAzIDI1NC40MTIgMTQyLjA0NEMyNTQuNDEyIDc5LjY4NDYgMjAzLjg2IDI5LjEzMjQgMTQxLjUwMSAyOS4xMzI0Qzc5LjE0MTUgMjkuMTMyNCAyOC41ODk0IDc5LjY4NDYgMjguNTg5NCAxNDIuMDQ0QzI4LjU4OTQgMjA0LjQwMyA3OS4xNDE1IDI1NC45NTUgMTQxLjUwMSAyNTQuOTU1WiIgZmlsbD0id2hpdGUiIHN0cm9rZT0idXJsKCNwYWludDBfbGluZWFyXzIwMV8xNTQpIiBzdHJva2Utd2lkdGg9IjE0LjExMzkiLz4KPHBhdGggZD0iTTE1NC4yMDQgMTIzLjY5NlY1MC4zMDM2TDk5LjE1OTcgMTYwLjM5MkgxMzUuODU2VjIzMy43ODRMMTkwLjkgMTIzLjY5NkgxNTQuMjA0WiIgZmlsbD0idXJsKCNwYWludDFfbGluZWFyXzIwMV8xNTQpIi8+CjxwYXRoIGQ9Ik0yODAuNDM2IDE0Mi4wNDRDMjgwLjQzNiA2NS4zMTMxIDIxOC4yMzMgMy4xMTAzNSAxNDEuNTAyIDMuMTEwMzVDNjQuNzcwNyAzLjExMDM1IDIuNTY3ODcgNjUuMzEzMSAyLjU2Nzg3IDE0Mi4wNDRDMi41Njc4NyAyMTguNzc1IDY0Ljc3MDcgMjgwLjk3OCAxNDEuNTAyIDI4MC45NzhDMjE4LjIzMyAyODAuOTc4IDI4MC40MzYgMjE4Ljc3NSAyODAuNDM2IDE0Mi4wNDRaIiBzdHJva2U9InVybCgjcGFpbnQyX2xpbmVhcl8yMDFfMTU0KSIgc3Ryb2tlLXdpZHRoPSI0LjQxMDYiLz4KPGRlZnM+CjxsaW5lYXJHcmFkaWVudCBpZD0icGFpbnQwX2xpbmVhcl8yMDFfMTU0IiB4MT0iMjEuNTMyNCIgeTE9IjIyLjA3NTYiIHgyPSIyNjYuODk2IiB5Mj0iNzcuMDcwOCIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgo8c3RvcCBzdG9wLWNvbG9yPSIjM0IwMEI5Ii8+CjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzI1ODZCNiIvPgo8L2xpbmVhckdyYWRpZW50Pgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MV9saW5lYXJfMjAxXzE1NCIgeDE9Ijk5LjE1OTciIHkxPSI1MC4zMDM2IiB4Mj0iMTk2LjQ2NiIgeTI9IjYxLjIwODQiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KPHN0b3Agc3RvcC1jb2xvcj0iIzNCMDBCOSIvPgo8c3RvcCBvZmZzZXQ9IjEiIHN0b3AtY29sb3I9IiMyNTg2QjYiLz4KPC9saW5lYXJHcmFkaWVudD4KPGxpbmVhckdyYWRpZW50IGlkPSJwYWludDJfbGluZWFyXzIwMV8xNTQiIHgxPSIwLjM2MjU3MyIgeTE9IjAuOTA1MDUxIiB4Mj0iMjg5LjAyNSIgeTI9IjY1LjYwNSIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgo8c3RvcCBzdG9wLWNvbG9yPSIjM0IwMEI5Ii8+CjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzI1ODZCNiIvPgo8L2xpbmVhckdyYWRpZW50Pgo8L2RlZnM+Cjwvc3ZnPgo=";
pub const MAX_MEMO_LENGTH: u64 = 32;
pub const PERMITTED_DRIFT: Duration = Duration::from_secs(60);
pub const TRANSACTION_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
// The maximum number of transactions in the transaction-to-hash and block-timestamp-to-block-index mappings to be pruned in a single prune process
pub const TRANSACTION_PRUNE_LIMIT: usize = 100_000;
// The maximum number of entries in the approval list and expiration queue to be pruned in a single prune process
pub const APPROVE_PRUNE_LIMIT: usize = 100;
pub const REMOTE_FUTURE: u64 = u64::MAX;
pub const MAX_TAKE_ALLOWANCES: u64 = 500;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Config {
    /// The maximum number of blocks
    /// returned by the [icrc3_get_blocks]
    /// endpoint
    pub max_blocks_per_request: u64,

    /// The principal of the index canister
    /// for this ledger
    pub index_id: Option<Principal>,

    /// The initial balances of the ledger.
    /// No fee will be charged for minting these initial balances.
    /// Cycles covering the total initial balances need to be deposited, otherwise unexpected errors may occur.
    pub initial_balances: Option<Vec<(Account, u128)>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_blocks_per_request: 100,
            index_id: None,
            initial_balances: None,
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
        max_blocks_per_request: 10,
        index_id: None,
        initial_balances: None,
    };
    assert_eq!(Config::from_bytes(config.to_bytes()), config);
}
