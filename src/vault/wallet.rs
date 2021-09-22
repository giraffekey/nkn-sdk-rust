use crate::constant::{DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT};
use crate::crypto::ScryptConfig;
use crate::vault::account::AccountHolder;
use crate::vault::data::WalletData;
use crate::{
    Account, NanoPay, NanoPayClaimer, RPCClient, Registrant, SignerRPCClient, Subscribers,
    Subscription, Transaction, TransactionConfig,
};

pub struct WalletConfig {
    pub rpc_server_address: Vec<String>,
    pub rpc_timeout: u32,
    pub rpc_concurrency: u32,
    pub password: String,
    pub master_key: Vec<u8>,
    pub iv: Vec<u8>,
    pub scrypt_config: ScryptConfig,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            rpc_server_address: Vec::new(),
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            rpc_concurrency: DEFAULT_RPC_CONCURRENCY,
            password: String::new(),
            iv: Vec::new(),
            master_key: Vec::new(),
            scrypt_config: ScryptConfig::default(),
        }
    }
}

pub struct Wallet<'a> {
    config: WalletConfig,
    account: &'a Account,
    wallet_data: WalletData,
}

impl<'a> Wallet<'a> {
    pub fn new(account: &'a Account, config: WalletConfig) -> Self {
        let wallet_data = WalletData::new(account, &config.password, &config.master_key, &config.iv, config.scrypt_config.clone());

        Self {
            config,
            account,
            wallet_data,
        }
    }

    pub fn from_json(json: &str, config: WalletConfig) -> Self {
        todo!()
    }

    pub fn to_json(&self) -> String {
        todo!()
    }

    pub fn config(&self) -> &WalletConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: WalletConfig) {
        self.config = config
    }

    pub fn verify_password(password: &str) -> bool {
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
}

impl AccountHolder for Wallet<'_> {
    fn account(&self) -> &Account {
        self.account
    }

    fn public_key(&self) -> &[u8] {
        self.account.public_key()
    }

    fn private_key(&self) -> &[u8] {
        self.account.private_key()
    }

    fn seed(&self) -> &[u8] {
        self.account.seed()
    }

    fn address(&self) -> String {
        self.account.wallet_address()
    }

    fn program_hash(&self) -> &[u8] {
        self.account.program_hash()
    }
}

impl RPCClient for Wallet<'_> {
    fn nonce(&self, tx_pool: bool) -> u64 {
        todo!()
    }

    fn nonce_by_address(&self, address: &str, tx_pool: bool) -> u64 {
        todo!()
    }

    fn balance(&self) -> u64 {
        todo!()
    }

    fn balance_by_address(&self, address: &str) -> u64 {
        todo!()
    }

    fn height(&self) -> u32 {
        todo!()
    }

    fn subscribers(
        &self,
        topic: &str,
        offset: u32,
        limit: u32,
        meta: bool,
        tx_pool: bool,
    ) -> Subscribers {
        todo!()
    }

    fn subscription(&self, topic: &str, subscriber: &str) -> Subscription {
        todo!()
    }

    fn suscribers_count(&self, topic: &str) -> u32 {
        todo!()
    }

    fn registrant(&self, name: &str) -> Registrant {
        todo!()
    }

    fn send_raw_transaction(&self, txn: Transaction) -> String {
        todo!()
    }
}

impl SignerRPCClient for Wallet<'_> {
    fn sign_transaction(&self, tx: Transaction) {
        todo!()
    }

    fn transfer(address: &str, amount: u64, config: TransactionConfig) -> String {
        todo!()
    }

    fn register_name(&self, name: &str, config: TransactionConfig) -> String {
        todo!()
    }

    fn transfer_name(name: &str, recipient_public_key: &[u8], config: TransactionConfig) -> String {
        todo!()
    }

    fn delete_name(&self, name: &str, config: TransactionConfig) -> String {
        todo!()
    }

    fn subscribe(
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        config: TransactionConfig,
    ) -> String {
        todo!()
    }

    fn unsubscribe(identifier: &str, topic: &str, config: TransactionConfig) -> String {
        todo!()
    }
}
