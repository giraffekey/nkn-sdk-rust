use crate::constant::{DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT};
use crate::crypto::ScryptConfig;
use crate::nanopay::{NanoPay, NanoPayClaimer};
use crate::rpc::{RPCClient, Registrant, SignerRPCClient, Subscribers, Subscription};
use crate::transaction::{Transaction, TransactionConfig};
use crate::vault::data::{
    WalletData, IV_LEN, MAX_COMPATIBLE_WALLET_VERSION, MIN_COMPATIBLE_WALLET_VERSION,
};
use crate::vault::{Account, AccountHolder};

use rand::Rng;

#[derive(Debug)]
pub struct WalletConfig {
    pub rpc_server_address: Vec<String>,
    pub rpc_timeout: u32,
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

impl RPCClient for Wallet {
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

impl SignerRPCClient for Wallet {
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
