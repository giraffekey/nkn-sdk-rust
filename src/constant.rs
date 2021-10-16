use std::time::Duration;

pub const DEFAULT_SEED_RPC_SERVER: &[&str] = &["http://seed.nkn.org:30003"];
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_RPC_CONCURRENCY: u32 = 10000;
pub const STORAGE_FACTOR: i64 = 1_0000_0000;
pub const MIN_NAME_REGISTRATION_FEE: i64 = 10 * STORAGE_FACTOR;
pub const MAXIMUM_PRECISION: usize = 8;
