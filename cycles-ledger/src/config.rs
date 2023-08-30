use std::time::Duration;

pub const FEE: u128 = 100_000_000;
pub const DECIMALS: u8 = 0;
pub const TOKEN_NAME: &str = "ICP Cycles";
pub const TOKEN_SYMBOL: &str = "CYC";
pub const MAX_MEMO_LENGTH: u32 = 32;
pub const PERMITTED_DRIFT: Duration = Duration::from_secs(60);
pub const TRANSACTION_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
// The maximum number of transactions in the transaction to hash and block timestamp to block index mappings to be pruned in a single prune process
pub const TRANSACTION_PRUNE_LIMIT: usize = 100_000;
// The maximum number of entries in the approval list and expiration queue to be pruned in a single prune process
pub const APPROVE_PRUNE_LIMIT: usize = 100;
