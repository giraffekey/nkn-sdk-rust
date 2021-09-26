use crate::constant::{DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT};
use crate::nanopay::{NanoPay, NanoPayClaimer};
use crate::program::{create_signature_program_context, Program};
use crate::rpc::{
    delete_name, get_balance, get_height, get_nonce, get_registrant, get_subscribers,
    get_subscribers_count, get_subscription, register_name, send_raw_transaction, subscribe,
    transfer, transfer_name, unsubscribe, RPCClient, RPCConfig, Registrant, SignerRPCClient,
    Subscribers, Subscription,
};
use crate::signature::{sign_by_signer, SignableData, Signer};
use crate::transaction::{Transaction, TransactionConfig};
use crate::vault::data::{
    WalletData, IV_LEN, MAX_COMPATIBLE_WALLET_VERSION, MIN_COMPATIBLE_WALLET_VERSION,
};
use crate::vault::{Account, AccountHolder, ScryptConfig};

use async_trait::async_trait;
use rand::Rng;
use std::time::Duration;

#[derive(Debug)]
pub struct WalletConfig {
    pub rpc_server_address: Vec<String>,
    pub rpc_timeout: Duration,
    pub rpc_concurrency: u32,
    pub password: String,
    pub master_key: Vec<u8>,
    pub iv: [u8; IV_LEN],
    pub scrypt: ScryptConfig,
}

impl Default for WalletConfig {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let mut master_key = [0u8; 32];
        rng.fill(&mut master_key);
        let mut iv = [0u8; IV_LEN];
        rng.fill(&mut iv);

        Self {
            rpc_server_address: Vec::new(),
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            rpc_concurrency: DEFAULT_RPC_CONCURRENCY,
            password: String::new(),
            master_key: master_key.to_vec(),
            iv,
            scrypt: ScryptConfig::default(),
        }
    }
}

pub struct Wallet {
    config: WalletConfig,
    account: Account,
    wallet_data: WalletData,
}

impl Wallet {
    pub fn new(account: Account, config: WalletConfig) -> Result<Self, String> {
        let wallet_data = WalletData::new(
            &account,
            &config.password,
            &config.master_key,
            config.iv,
            ScryptConfig { ..config.scrypt },
        )?;

        let config = WalletConfig {
            password: String::new(),
            master_key: Vec::new(),
            ..config
        };

        Ok(Self {
            config,
            account,
            wallet_data,
        })
    }

    pub fn from_json(json: &str, config: WalletConfig) -> Result<Self, String> {
        let wallet_data: WalletData =
            serde_json::from_str(json).map_err(|_| "Invalid JSON".to_string())?;

        if wallet_data.version < MIN_COMPATIBLE_WALLET_VERSION
            || wallet_data.version > MAX_COMPATIBLE_WALLET_VERSION
        {
            return Err("Incompatible wallet version".into());
        }

        let account = wallet_data.decrypt_account(&config.password)?;
        if account.wallet_address() != wallet_data.address {
            return Err("Wrong password".into());
        }

        let config = WalletConfig {
            password: String::new(),
            master_key: Vec::new(),
            ..config
        };

        Ok(Self {
            config,
            account,
            wallet_data,
        })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.wallet_data).unwrap()
    }

    pub fn config(&self) -> &WalletConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: WalletConfig) {
        self.config = config
    }

    pub fn verify_password(&self, password: &str) -> Result<bool, String> {
        let account = self.wallet_data.decrypt_account(password)?;
        Ok(account.wallet_address() == self.wallet_data.address)
    }

    pub fn create_nano_pay(&self, recipient_address: &str, fee: u64, duration: u32) -> NanoPay {
        NanoPay::new(self, self, recipient_address, fee, duration)
    }

    pub fn create_nano_pay_claimer(
        &self,
        recipient_address: &str,
        claim_interval_ms: u32,
        min_flush_amount: u64,
    ) -> NanoPayClaimer {
        NanoPayClaimer::new(self, recipient_address, claim_interval_ms, min_flush_amount)
    }
}

impl AccountHolder for Wallet {
    fn account(&self) -> &Account {
        &self.account
    }

    fn public_key(&self) -> &[u8] {
        self.account.public_key()
    }

    fn private_key(&self) -> &[u8] {
        self.account.private_key()
    }

    fn seed(&self) -> Vec<u8> {
        self.account.seed()
    }

    fn address(&self) -> String {
        self.account.wallet_address()
    }

    fn program_hash(&self) -> &[u8] {
        self.account.program_hash()
    }
}

fn config_to_rpc_config(config: &WalletConfig) -> RPCConfig {
    RPCConfig {
        rpc_server_address: config.rpc_server_address.clone(),
        rpc_timeout: config.rpc_timeout,
        rpc_concurrency: config.rpc_concurrency,
    }
}

#[async_trait]
impl RPCClient for Wallet {
    async fn nonce(&self, tx_pool: bool) -> u64 {
        self.nonce_by_address(&self.address(), tx_pool).await
    }

    async fn nonce_by_address(&self, address: &str, tx_pool: bool) -> u64 {
        get_nonce(address, tx_pool, config_to_rpc_config(&self.config)).await
    }

    async fn balance(&self) -> u64 {
        self.balance_by_address(&self.address()).await
    }

    async fn balance_by_address(&self, address: &str) -> u64 {
        get_balance(address, config_to_rpc_config(&self.config)).await
    }

    async fn height(&self) -> u32 {
        get_height(config_to_rpc_config(&self.config)).await
    }

    fn subscribers(
        &self,
        topic: &str,
        offset: u32,
        limit: u32,
        meta: bool,
        tx_pool: bool,
    ) -> Subscribers {
        get_subscribers(
            topic,
            offset,
            limit,
            meta,
            tx_pool,
            config_to_rpc_config(&self.config),
        )
    }

    fn subscription(&self, topic: &str, subscriber: &str) -> Subscription {
        get_subscription(topic, subscriber, config_to_rpc_config(&self.config))
    }

    fn suscribers_count(&self, topic: &str, subscriber_hash_prefix: &[u8]) -> u32 {
        get_subscribers_count(
            topic,
            subscriber_hash_prefix,
            config_to_rpc_config(&self.config),
        )
    }

    fn registrant(&self, name: &str) -> Registrant {
        get_registrant(name, config_to_rpc_config(&self.config))
    }

    fn send_raw_transaction(&self, txn: Transaction) -> String {
        send_raw_transaction(txn, config_to_rpc_config(&self.config))
    }
}

impl SignerRPCClient for Wallet {
    fn sign_transaction(&self, tx: &mut Transaction) {
        let ct = create_signature_program_context(self.account.public_key());
        let signature = sign_by_signer(tx, &self.account);
        tx.set_programs(vec![Program::new(&ct, &signature)]);
    }

    fn transfer(&self, address: &str, amount: u64, config: TransactionConfig) -> String {
        transfer(self, address, amount, config)
    }

    fn register_name(&self, name: &str, config: TransactionConfig) -> String {
        register_name(self, name, config)
    }

    fn transfer_name(
        &self,
        name: &str,
        recipient_public_key: &[u8],
        config: TransactionConfig,
    ) -> String {
        transfer_name(self, name, recipient_public_key, config)
    }

    fn delete_name(&self, name: &str, config: TransactionConfig) -> String {
        delete_name(self, name, config)
    }

    fn subscribe(
        &self,
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        config: TransactionConfig,
    ) -> String {
        subscribe(self, identifier, topic, duration, meta, config)
    }

    fn unsubscribe(&self, identifier: &str, topic: &str, config: TransactionConfig) -> String {
        unsubscribe(self, identifier, topic, config)
    }
}
