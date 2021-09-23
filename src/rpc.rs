use crate::constant::{DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT};
use crate::transaction::{Transaction, TransactionConfig};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use std::collections::HashMap;

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

#[derive(Debug)]
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

#[derive(Debug)]
pub struct Node {
    pub address: String,
    pub rpc_address: String,
    pub public_key: Vec<u8>,
    pub id: String,
}

pub fn get_ws_address(client_address: &str, config: RPCConfig) -> Node {
    todo!()
}

pub fn get_wss_address(client_address: &str, config: RPCConfig) -> Node {
    todo!()
}

#[derive(Debug)]
pub struct NodeState {
    pub address: String,
    pub current_timestamp: u64,
    pub height: u32,
    pub id: String,
    pub json_rpc_port: u32,
    pub proposal_submitted: u32,
    pub protocol_version: u32,
    pub public_key: Vec<u8>,
    pub relay_message_count: u64,
    pub sync_state: String,
    pub tls_json_rpc_domain: String,
    pub tls_json_rpc_port: u32,
    pub tls_websocket_domain: String,
    pub tls_websocket_port: u32,
    pub uptime: u64,
    pub version: String,
    pub websocket_port: u32,
}

pub fn get_node_state(config: RPCConfig) -> NodeState {
    todo!()
}

#[derive(Debug)]
pub struct Registrant {
    pub registrant: String,
    pub expires_at: u64,
}

pub fn get_registrant(name: &str, config: RPCConfig) -> Registrant {
    todo!()
}

#[derive(Debug)]
pub struct Subscription {
    pub meta: String,
    pub expires_at: u64,
}

pub fn get_subscription(topic: &str, subscriber: &str, config: RPCConfig) -> Subscription {
    todo!()
}

#[derive(Debug)]
pub struct Subscribers {
    pub map: HashMap<String, String>,
    pub tx_pool_map: HashMap<String, String>,
}

pub fn get_subscribers(
    topic: &str,
    offset: u32,
    limit: u32,
    meta: bool,
    tx_pool: bool,
    config: RPCConfig,
) -> Subscribers {
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

pub fn measure_rpc_server(rpc_list: &[&str], timeout: u32) -> Vec<String> {
    todo!()
}
