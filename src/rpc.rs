use crate::constant::{DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value as JsonValue};

pub struct Node {
    address: String,
    rpc_address: String,
    public_key: Vec<u8>,
    identifier: String,
}

pub struct Registrant {
    registrant: String,
    expires_at: u64,
}

pub struct Subscription {
    meta: String,
    expires_at: u64,
}

pub struct RPCConfig {
    pub rpc_server_address: Vec<String>,
    pub rpc_timeout: u32,
    pub rpc_concurrency: u32,
}

impl Default for RPCConfig {
    fn default() -> Self {
        Self {
            rpc_server_address: Vec::new(),
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            rpc_concurrency: DEFAULT_RPC_CONCURRENCY,
        }
    }
}

pub fn rpc_call<S: Serialize, D: DeserializeOwned>(
    method: &str,
    params: S,
    config: RPCConfig,
) -> D {
    todo!()
}

pub fn get_balance(address: &str, config: RPCConfig) -> u64 {
    rpc_call("getbalancebyaddr", json! {"address": address}, config)
}
