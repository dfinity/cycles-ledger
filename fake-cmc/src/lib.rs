use cycles_ledger::endpoints::{CmcCreateCanisterArgs, CmcCreateCanisterError};
use serde::Deserialize;

#[derive(Debug, Deserialize, Eq, PartialEq, Default)]
pub struct State {
    pub last_creat_canister_args: Option<CmcCreateCanisterArgs>,
    pub fail_next_create_canister_with: Option<CmcCreateCanisterError>,
}
