use crate::constant::{DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT, DEFAULT_SEED_RPC_SERVER};
use crate::crypto::ed25519_private_key_to_curve25519_private_key;
use crate::message::MessageConfig;
use crate::nano_pay::{NanoPay, NanoPayClaimer};
use crate::rpc::{
    get_balance, Node, RPCClient, RPCConfig, Registrant, SignerRPCClient, Subscribers, Subscription,
};
use crate::signature::Signer;
use crate::transaction::{Transaction, TransactionConfig};
use crate::vault::{Account, AccountHolder, Wallet, WalletConfig};

use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug)]
pub struct ClientConfig {
    pub rpc_server_address: Vec<String>,
    pub rpc_timeout: Duration,
    pub rpc_concurrency: u32,
    pub msg_chan_length: u32,
    pub connect_retries: u32,
    pub msg_cache_expiration: u32,
    pub msg_cache_cleanup_interval: u32,
    pub ws_handshake_timeout: u32,
    pub ws_write_timeout: u32,
    pub min_reconnect_interval: u32,
    pub max_reconnect_interval: u32,
    pub default_message_config: Option<MessageConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            rpc_server_address: DEFAULT_SEED_RPC_SERVER
                .iter()
                .map(|s| s.to_string())
                .collect(),
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            rpc_concurrency: DEFAULT_RPC_CONCURRENCY,
            msg_chan_length: 1024,
            connect_retries: 3,
            msg_cache_expiration: 300000,
            msg_cache_cleanup_interval: 60000,
            ws_handshake_timeout: 5000,
            ws_write_timeout: 10000,
            min_reconnect_interval: 1000,
            max_reconnect_interval: 64000,
            default_message_config: None,
        }
    }
}

pub struct Client {
    config: ClientConfig,
    account: Account,
    wallet: Wallet,
    identifier: Option<String>,
    curve_secret_key: Vec<u8>,
}

impl Client {
    pub fn new(
        account: Account,
        identifier: Option<String>,
        config: ClientConfig,
    ) -> Result<Self, String> {
        let wallet_config = WalletConfig {
            rpc_server_address: config.rpc_server_address.clone(),
            ..WalletConfig::default()
        };
        let wallet = Wallet::new(account.clone(), wallet_config)?;
        let curve_secret_key = ed25519_private_key_to_curve25519_private_key(account.private_key());

        Ok(Self {
            config,
            account,
            wallet,
            identifier,
            curve_secret_key,
        })
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: ClientConfig) {
        self.config = config
    }

    pub fn close(&self) {
        todo!()
    }

    pub fn is_closed(&self) -> bool {
        todo!()
    }

    pub fn reconnect(&self) {
        todo!()
    }

    pub fn node(&self) -> Node {
        todo!()
    }

    pub fn publish(&self, topic: &str, data: impl Into<Vec<u8>>, config: MessageConfig) {
        todo!()
    }

    pub fn publish_binary(&self, topic: &str, data: &[u8], config: MessageConfig) {
        self.publish(topic, data, config)
    }

    pub fn publish_text(&self, topic: &str, data: &str, config: MessageConfig) {
        self.publish(topic, data, config)
    }

    pub fn send(&self, dests: &[&str], data: impl Into<Vec<u8>>, config: MessageConfig) {
        todo!()
    }

    pub fn send_binary(&self, dests: &[&str], data: &[u8], config: MessageConfig) {
        self.send(dests, data, config)
    }

    pub fn send_text(&self, dests: &[&str], data: &str, config: MessageConfig) {
        self.send(dests, data, config)
    }

    pub fn set_write_deadline(&self, deadline: u64) {
        todo!()
    }

    pub fn create_nano_pay(&self, recipient_address: &str, fee: i64, duration: u32) -> NanoPay {
        todo!()
    }

    pub fn create_nano_pay_claimer(
        &self,
        recipient_address: &str,
        claim_interval_ms: u32,
        min_flush_amount: i64,
    ) -> NanoPayClaimer {
        todo!()
    }
}

impl AccountHolder for Client {
    fn account(&self) -> &Account {
        &self.account
    }

    fn seed(&self) -> Vec<u8> {
        self.account.seed()
    }

    fn address(&self) -> String {
        let pub_key_hex = hex::encode(self.public_key());
        if let Some(identifier) = &self.identifier {
            if !identifier.is_empty() {
                format!("{:?}.{:?}", identifier, pub_key_hex)
            } else {
                pub_key_hex
            }
        } else {
            pub_key_hex
        }
    }

    fn program_hash(&self) -> &[u8] {
        self.account.program_hash()
    }
}

impl Signer for Client {
    fn private_key(&self) -> &[u8] {
        self.account.private_key()
    }

    fn public_key(&self) -> &[u8] {
        self.account.public_key()
    }
}

fn config_to_rpc_config(config: &ClientConfig) -> RPCConfig {
    RPCConfig {
        rpc_server_address: config.rpc_server_address.clone(),
        rpc_timeout: config.rpc_timeout,
        rpc_concurrency: config.rpc_concurrency,
    }
}

#[async_trait]
impl RPCClient for Client {
    async fn nonce(&self, tx_pool: bool) -> Result<u64, String> {
        todo!()
    }

    async fn nonce_by_address(&self, address: &str, tx_pool: bool) -> Result<u64, String> {
        todo!()
    }

    async fn balance(&self) -> Result<i64, String> {
        self.balance_by_address(&self.wallet.address()).await
    }

    async fn balance_by_address(&self, address: &str) -> Result<i64, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_balance(address, config_to_rpc_config(&self.config)).await
        } else {
            get_balance(address, config_to_rpc_config(&self.config)).await
        }
    }

    async fn height(&self) -> Result<u32, String> {
        todo!()
    }

    async fn subscribers(
        &self,
        topic: &str,
        offset: u32,
        limit: u32,
        meta: bool,
        tx_pool: bool,
    ) -> Result<Subscribers, String> {
        todo!()
    }

    async fn subscription(&self, topic: &str, subscriber: &str) -> Result<Subscription, String> {
        todo!()
    }

    async fn suscribers_count(
        &self,
        topic: &str,
        subscriber_hash_prefix: &[u8],
    ) -> Result<u32, String> {
        todo!()
    }

    async fn registrant(&self, name: &str) -> Result<Registrant, String> {
        todo!()
    }

    async fn send_raw_transaction(&self, txn: Transaction) -> Result<String, String> {
        todo!()
    }
}

#[async_trait]
impl SignerRPCClient for Client {
    fn sign_transaction(&self, tx: &mut Transaction) {
        todo!()
    }

    async fn transfer(
        &self,
        address: &str,
        amount: i64,
        config: TransactionConfig,
    ) -> Result<String, String> {
        todo!()
    }

    async fn register_name(&self, name: &str, config: TransactionConfig) -> Result<String, String> {
        todo!()
    }

    async fn transfer_name(
        &self,
        name: &str,
        recipient_public_key: &[u8],
        config: TransactionConfig,
    ) -> Result<String, String> {
        todo!()
    }

    async fn delete_name(&self, name: &str, config: TransactionConfig) -> Result<String, String> {
        todo!()
    }

    async fn subscribe(
        &self,
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
        todo!()
    }

    async fn unsubscribe(
        &self,
        identifier: &str,
        topic: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
        todo!()
    }
}
