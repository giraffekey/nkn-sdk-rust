use crate::constant::{DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT, DEFAULT_SEED_RPC_SERVER};
use crate::crypto::ed25519_private_key_to_curve25519_private_key;
use crate::message::MessageConfig;
use crate::nano_pay::{NanoPay, NanoPayClaimer};
use crate::rpc::{
    delete_name, get_balance, get_height, get_nonce, get_registrant, get_subscribers,
    get_subscribers_count, get_subscription, register_name, send_raw_transaction, subscribe,
    transfer, transfer_name, unsubscribe, Node, RPCClient, RPCConfig, Registrant, SignerRPCClient,
    Subscribers, Subscription,
};
use crate::signature::Signer;
use crate::transaction::{Transaction, TransactionConfig};
use crate::util::{client_config_to_rpc_config, wallet_config_to_rpc_config};
use crate::vault::{Account, AccountHolder, Wallet, WalletConfig};

use async_trait::async_trait;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{task, time::sleep};

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
    pub min_reconnect_interval: u64,
    pub max_reconnect_interval: u64,
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
    closed: Arc<Mutex<bool>>,
    node: Option<Node>,
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

        let closed = Arc::new(Mutex::new(false));

        Ok(Self {
            config,
            account,
            wallet,
            identifier,
            curve_secret_key,
            closed,
            node: None,
        })
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: ClientConfig) {
        self.config = config;
    }

    pub fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap()
    }

    pub fn close(&mut self) {
        *self.closed.lock().unwrap() = true;
        todo!()
    }

    pub fn connection(&self) {
        todo!() // return WS connection
    }

    async fn connect(&self, max_retries: u32) -> Result<(), String> {
        todo!()
    }

    pub async fn reconnect(&mut self) -> Result<(), String> {
        if *self.closed.lock().unwrap() {
            return Ok(());
        }

        log::info!("Reconnect in {} ms...", self.config.min_reconnect_interval);
        sleep(Duration::from_millis(self.config.min_reconnect_interval)).await;

        if let Err(err) = self.connect(0).await {
            self.close();
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn node(&self) -> &Option<Node> {
        &self.node
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

    pub fn create_nano_pay(
        &self,
        recipient_address: &str,
        fee: i64,
        duration: u64,
    ) -> Result<NanoPay, String> {
        NanoPay::new(
            client_config_to_rpc_config(&self.config),
            &self.wallet,
            recipient_address,
            fee,
            duration,
        )
    }

    pub fn create_nano_pay_claimer(
        &self,
        recipient_address: &str,
        claim_interval_ms: u64,
        min_flush_amount: i64,
    ) -> Result<NanoPayClaimer, String> {
        let recipient_address = if recipient_address.is_empty() {
            self.wallet.address()
        } else {
            recipient_address.into()
        };
        NanoPayClaimer::new(
            client_config_to_rpc_config(&self.config),
            &recipient_address,
            claim_interval_ms,
            min_flush_amount,
        )
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

#[async_trait]
impl RPCClient for Client {
    async fn nonce(&self, tx_pool: bool) -> Result<u64, String> {
        self.nonce_by_address(&self.wallet.address(), tx_pool).await
    }

    async fn nonce_by_address(&self, address: &str, tx_pool: bool) -> Result<u64, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_nonce(address, tx_pool, client_config_to_rpc_config(&self.config)).await
        } else {
            get_nonce(
                address,
                tx_pool,
                wallet_config_to_rpc_config(&wallet_config),
            )
            .await
        }
    }

    async fn balance(&self) -> Result<i64, String> {
        self.balance_by_address(&self.wallet.address()).await
    }

    async fn balance_by_address(&self, address: &str) -> Result<i64, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_balance(address, client_config_to_rpc_config(&self.config)).await
        } else {
            get_balance(address, wallet_config_to_rpc_config(&wallet_config)).await
        }
    }

    async fn height(&self) -> Result<u64, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_height(client_config_to_rpc_config(&self.config)).await
        } else {
            get_height(wallet_config_to_rpc_config(&wallet_config)).await
        }
    }

    async fn subscribers(
        &self,
        topic: &str,
        offset: u32,
        limit: u32,
        meta: bool,
        tx_pool: bool,
    ) -> Result<Subscribers, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_subscribers(
                topic,
                offset,
                limit,
                meta,
                tx_pool,
                client_config_to_rpc_config(&self.config),
            )
            .await
        } else {
            get_subscribers(
                topic,
                offset,
                limit,
                meta,
                tx_pool,
                wallet_config_to_rpc_config(&wallet_config),
            )
            .await
        }
    }

    async fn subscription(&self, topic: &str, subscriber: &str) -> Result<Subscription, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_subscription(topic, subscriber, client_config_to_rpc_config(&self.config)).await
        } else {
            get_subscription(
                topic,
                subscriber,
                wallet_config_to_rpc_config(&wallet_config),
            )
            .await
        }
    }

    async fn suscribers_count(
        &self,
        topic: &str,
        subscriber_hash_prefix: &[u8],
    ) -> Result<u32, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_subscribers_count(
                topic,
                subscriber_hash_prefix,
                client_config_to_rpc_config(&self.config),
            )
            .await
        } else {
            get_subscribers_count(
                topic,
                subscriber_hash_prefix,
                wallet_config_to_rpc_config(&wallet_config),
            )
            .await
        }
    }

    async fn registrant(&self, name: &str) -> Result<Registrant, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_registrant(name, client_config_to_rpc_config(&self.config)).await
        } else {
            get_registrant(name, wallet_config_to_rpc_config(&wallet_config)).await
        }
    }

    async fn send_raw_transaction(&self, txn: &Transaction) -> Result<String, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            send_raw_transaction(txn, client_config_to_rpc_config(&self.config)).await
        } else {
            send_raw_transaction(txn, wallet_config_to_rpc_config(&wallet_config)).await
        }
    }
}

#[async_trait]
impl SignerRPCClient for Client {
    fn sign_transaction(&self, tx: &mut Transaction) {
        self.wallet.sign_transaction(tx);
    }

    async fn transfer(
        &self,
        address: &str,
        amount: i64,
        config: TransactionConfig,
    ) -> Result<String, String> {
        transfer(self, address, amount, config).await
    }

    async fn register_name(&self, name: &str, config: TransactionConfig) -> Result<String, String> {
        register_name(self, name, config).await
    }

    async fn transfer_name(
        &self,
        name: &str,
        recipient_public_key: &[u8],
        config: TransactionConfig,
    ) -> Result<String, String> {
        transfer_name(self, name, recipient_public_key, config).await
    }

    async fn delete_name(&self, name: &str, config: TransactionConfig) -> Result<String, String> {
        delete_name(self, name, config).await
    }

    async fn subscribe(
        &self,
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
        subscribe(self, identifier, topic, duration, meta, config).await
    }

    async fn unsubscribe(
        &self,
        identifier: &str,
        topic: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
        unsubscribe(self, identifier, topic, config).await
    }
}
