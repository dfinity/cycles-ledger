use candid::Principal;
use serde::{Deserialize, Serialize};

pub mod endpoints;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub ledger_id: Principal,
}

// This isn't really used but it makes it easier to deal
// with state because we don't have to use Option for when
// the state is not initialized.
impl Default for Config {
    fn default() -> Self {
        Self {
            ledger_id: Principal::management_canister(),
        }
    }
}
