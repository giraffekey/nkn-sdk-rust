use std::time::Duration;

pub const DEFAULT_SEED_RPC_SERVER: &[&str] = &["http://seed.nkn.org:30003"];
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_RPC_CONCURRENCY: u32 = 10000;
pub const STORAGE_FACTOR: u64 = 100000000;
pub const MIN_NAME_REGISTRATION_FEE: u64 = 10 * STORAGE_FACTOR;
