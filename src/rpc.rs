use crate::constant::{DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT};
use crate::{Client, MultiClient, Subscribers, Transaction, TransactionConfig, Wallet};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value as JsonValue};

pub trait RPCClient {
    fn nonce(&self, tx_pool: bool) -> u64;
    fn nonce_by_address(&self, address: &str, tx_pool: bool) -> u64;
    fn balance(&self) -> u64;
    fn balance_by_address(&self, address: &str) -> u64;
    fn height(&self) -> u32;
    fn subscribers(
        &self,
        topic: &str,
        offset: u32,
        limit: u32,
        meta: bool,
        tx_pool: bool,
    ) -> Subscribers;
    fn subscription(&self, topic: &str, subscriber: &str) -> Subscription;
    fn suscribers_count(&self, topic: &str) -> u32;
    fn registrant(&self, name: &str) -> Registrant;
    fn send_raw_transaction(&self, txn: Transaction) -> String;
}

pub trait SignerRPCClient {
    fn sign_transaction(&self, tx: Transaction);
    fn transfer(address: &str, amount: u64, config: TransactionConfig) -> String;
    fn register_name(&self, name: &str, config: TransactionConfig) -> String;
    fn transfer_name(name: &str, recipient_public_key: &[u8], config: TransactionConfig) -> String;
    fn delete_name(&self, name: &str, config: TransactionConfig) -> String;
    fn subscribe(
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        config: TransactionConfig,
    ) -> String;
    fn unsubscribe(identifier: &str, topic: &str, config: TransactionConfig) -> String;
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

pub struct Node {
    address: String,
    rpc_address: String,
    public_key: Vec<u8>,
    id: String,
}

pub fn get_ws_address(client_address: &str, config: RPCConfig) -> Node {
    todo!()
}

pub fn get_wss_address(client_address: &str, config: RPCConfig) -> Node {
    todo!()
}

pub struct NodeState {
    address: String,
    current_timestamp: u64,
    height: u32,
    id: String,
    json_rpc_port: u32,
    proposal_submitted: u32,
    protocol_version: u32,
    public_key: Vec<u8>,
    relay_message_count: u64,
    sync_state: String,
    tls_json_rpc_domain: String,
    tls_json_rpc_port: u32,
    tls_websocket_domain: String,
    tls_websocket_port: u32,
    uptime: u64,
    version: String,
    websocket_port: u32,
}

pub fn get_node_state(config: RPCConfig) -> NodeState {
    todo!()
}

pub struct Registrant {
    registrant: String,
    expires_at: u64,
}

pub fn get_registrant(name: &str, config: RPCConfig) -> Registrant {
    todo!()
}

pub struct Subscription {
    meta: String,
    expires_at: u64,
}

pub fn get_subscription(topic: &str, subscriber: &str, config: RPCConfig) -> Subscription {
    todo!()
}

pub fn rpc_call<S: Serialize, D: DeserializeOwned>(
    method: &str,
    params: S,
    config: RPCConfig,
) -> D {
    todo!()
}

pub fn get_balance(address: &str, config: RPCConfig) -> u64 {
    rpc_call("getbalancebyaddr", json!({ "address": address }), config)
}
