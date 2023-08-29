use std::time::Duration;

pub const FEE: u128 = 100_000_000;
pub const DECIMALS: u8 = 0;
pub const TOKEN_NAME: &str = "ICP Cycles";
pub const TOKEN_SYMBOL: &str = "CYC";
pub const MAX_MEMO_LENGTH: u32 = 32;
pub const PERMITTED_DRIFT: Duration = Duration::from_secs(60);
pub const TRANSACTION_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
pub const MAX_TRANSACTIONS_TO_PURGE: usize = 100_000;
pub const APPROVE_PRUNE_LIMIT: usize = 100;
