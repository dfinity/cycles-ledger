use cycles_ledger::endpoints::{CmcCreateCanisterArgs, CmcCreateCanisterError};
use serde::Deserialize;

#[derive(Debug, Deserialize, Eq, PartialEq, Default)]
pub struct State {
    pub last_create_canister_args: Option<CmcCreateCanisterArgs>,
    pub fail_next_create_canister_with: Option<CmcCreateCanisterError>,
}

#[derive(CandidType, Deserialize)]
pub struct IcpXdrConversionRateResponse {
    pub certificate: serde_bytes::ByteBuf,
    pub data: IcpXdrConversionRate,
    pub hash_tree: serde_bytes::ByteBuf,
}

impl Default for IcpXdrConversionRateResponse {
    fn default() -> Self {
        Self {
            certificate: Default::default(),
            data: Default::default(),
            hash_tree: Default::default(),
        }
    }
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
            timestamp_seconds: Time(),
        }
    }
}
