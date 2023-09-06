use candid::Deserialize;
use ic_canister_log::declare_log_buffer;
use serde;

// High-priority messages.
declare_log_buffer!(name = P0, capacity = 1000);

// Low-priority info messages.
declare_log_buffer!(name = P1, capacity = 1000);

#[derive(Clone, serde::Serialize, Deserialize, Debug)]
pub enum Priority {
    P0,
    P1,
}

#[derive(Clone, serde::Serialize, Deserialize, Debug)]
pub struct LogEntry {
    pub timestamp: u64,
    pub priority: Priority,
    pub file: String,
    pub line: u32,
    pub message: String,
}

#[derive(Clone, Default, serde::Serialize, Deserialize, Debug)]
pub struct Log {
    pub entries: Vec<LogEntry>,
}
