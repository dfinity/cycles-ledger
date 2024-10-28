use candid::CandidType;
use cycles_ledger::endpoints::{CmcCreateCanisterArgs, CmcCreateCanisterError};
use ic_cdk::api::time;
use serde::Deserialize;

const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

#[derive(Debug, Deserialize, Eq, PartialEq, Default)]
pub struct State {
    pub last_create_canister_args: Option<CmcCreateCanisterArgs>,
    pub fail_next_create_canister_with: Option<CmcCreateCanisterError>,
}

#[derive(CandidType, Deserialize, Default)]
pub struct IcpXdrConversionRateResponse {
    pub certificate: Vec<u8>,
    pub data: IcpXdrConversionRate,
    pub hash_tree: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct IcpXdrConversionRate {
    pub xdr_permyriad_per_icp: u64,
    pub timestamp_seconds: u64,
}

impl Default for IcpXdrConversionRate {
    fn default() -> Self {
        Self {
            // mocked value
            xdr_permyriad_per_icp: 50_000,
            timestamp_seconds: time() / NANOSECONDS_PER_SECOND,
        }
    }
}
