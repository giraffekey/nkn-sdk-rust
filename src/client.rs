use crate::constant::{DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT};
use crate::{
    get_balance, Account, MessageConfig, NanoPay, NanoPayClaimer, Node, RPCConfig, Registrant,
    Subscribers, Subscription, Transaction, TransactionConfig, Wallet, WalletConfig,
};

pub struct ClientConfig {
    pub rpc_server_address: Vec<String>,
    pub rpc_timeout: u32,
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
            rpc_server_address: Vec::new(),
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

pub struct Client<'a> {
    account: &'a Account,
    identifier: Option<String>,
    config: ClientConfig,
    wallet: Wallet<'a>,
}

impl<'a> Client<'a> {
    pub fn new(account: &'a Account, identifier: Option<String>, config: ClientConfig) -> Self {
        let wallet_config = WalletConfig {
            rpc_server_address: config.rpc_server_address.clone(),
            ..WalletConfig::default()
        };
        let wallet = Wallet::new(account, wallet_config);

        Self {
            account,
            identifier,
            config,
            wallet,
        }
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: ClientConfig) {
        self.config = config
    }

    pub fn account(&self) -> &Account {
        self.account
    }

    pub fn public_key(&self) -> &[u8] {
        self.account.public_key()
    }

    pub fn seed(&self) -> &[u8] {
        self.account.seed()
    }

    pub fn address(&self) -> String {
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

    pub fn balance(&self) -> u64 {
        self.balance_by_address(self.wallet.address())
    }

    pub fn balance_by_address(&self, address: &str) -> u64 {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_balance(
                address,
                RPCConfig {
                    rpc_server_address: self.config.rpc_server_address,
                    rpc_timeout: self.config.rpc_timeout,
                    rpc_concurrency: self.config.rpc_concurrency,
                },
            )
        } else {
            get_balance(
                address,
                RPCConfig {
                    rpc_server_address: wallet_config.rpc_server_address,
                    rpc_timeout: wallet_config.rpc_timeout,
                    rpc_concurrency: wallet_config.rpc_concurrency,
                },
            )
        }
    }

    pub fn close(&self) {
        todo!()
    }

    pub fn height(&self) -> u32 {
        todo!()
    }

    pub fn node(&self) -> Node {
        todo!()
    }

    pub fn nonce(&self, tx_pool: bool) -> u64 {
        todo!()
    }

    pub fn nonce_by_address(&self, address: &str, tx_pool: bool) -> u64 {
        todo!()
    }

    pub fn registrant(&self, name: &str) -> Registrant {
        todo!()
    }

    pub fn subscribers(
        &self,
        topic: &str,
        offset: u32,
        limit: u32,
        meta: bool,
        tx_pool: bool,
    ) -> Subscribers {
        todo!()
    }

    pub fn suscribers_count(&self, topic: &str) -> u32 {
        todo!()
    }

    pub fn subscription(&self, topic: &str, subscriber: &str) -> Subscription {
        todo!()
    }

    pub fn is_closed(&self) -> bool {
        todo!()
    }

    pub fn create_nano_pay(&self, recipient_address: &str, fee: &str, duration: u32) -> NanoPay {
        todo!()
    }

    pub fn create_nano_pay_claimer(
        &self,
        recipient_address: &str,
        claim_interval_ms: u32,
        min_flush_amount: u64,
    ) -> NanoPayClaimer {
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

    pub fn reconnect(&self) {
        todo!()
    }

    pub fn register_name(&self, name: &str, config: TransactionConfig) -> String {
        todo!()
    }

    pub fn delete_name(&self, name: &str, config: TransactionConfig) -> String {
        todo!()
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

    pub fn send_raw_transaction(&self, txn: Transaction) -> String {
        todo!()
    }

    pub fn set_write_deadline(&self, deadline: u64) {
        todo!()
    }

    pub fn sign_transaction(&self, tx: Transaction) {
        todo!()
    }

    pub fn subscribe(
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        config: TransactionConfig,
    ) -> String {
        todo!()
    }

    pub fn transfer(address: &str, amount: u64, config: TransactionConfig) -> String {
        todo!()
    }

    pub fn transfer_name(
        name: &str,
        recipient_public_key: &[u8],
        config: TransactionConfig,
    ) -> String {
        todo!()
    }

    pub fn unsubscribe(identifier: &str, topic: &str, config: TransactionConfig) -> String {
        todo!()
    }
}
