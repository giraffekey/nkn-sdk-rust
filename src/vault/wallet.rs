use crate::constant::{
    DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT, DEFAULT_SEED_RPC_SERVER,
    MIN_NAME_REGISTRATION_FEE,
};
use crate::crypto::{IV_LEN, SEED_LEN};
use crate::nano_pay::{NanoPay, NanoPayClaimer};
use crate::program::{
    create_program_hash, create_signature_program_context, to_script_hash, Program,
};
use crate::rpc::{
    get_balance, get_height, get_nonce, get_registrant, get_subscribers, get_subscribers_count,
    get_subscription, send_raw_transaction, RPCConfig, Registrant, Subscribers, Subscription,
};
use crate::signature::{sign, SignableData};
use crate::transaction::{Transaction, TransactionConfig};
use crate::util::wallet_config_to_rpc_config;
use crate::vault::data::{
    WalletData, MAX_COMPATIBLE_WALLET_VERSION, MIN_COMPATIBLE_WALLET_VERSION,
};
use crate::vault::{Account, AccountHolder, ScryptConfig};

use rand::Rng;
use std::{sync::Arc, time::Duration};

#[derive(Debug, Clone)]
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
            rpc_server_address: DEFAULT_SEED_RPC_SERVER
                .iter()
                .map(|s| s.to_string())
                .collect(),
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            rpc_concurrency: DEFAULT_RPC_CONCURRENCY,
            password: String::new(),
            master_key: master_key.to_vec(),
            iv,
            scrypt: ScryptConfig::default(),
        }
    }
}

#[derive(Clone)]
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
            config.scrypt.clone(),
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

    pub fn config(&self) -> &WalletConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: WalletConfig) {
        self.config = config
    }

    pub fn public_key(&self) -> &[u8] {
        self.account.public_key()
    }

    pub fn private_key(&self) -> &[u8] {
        self.account.private_key()
    }

    pub fn verify_address(address: &str) -> bool {
        to_script_hash(address).is_ok()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.wallet_data).unwrap()
    }

    pub fn verify_password(&self, password: &str) -> Result<bool, String> {
        let account = self.wallet_data.decrypt_account(password)?;
        Ok(account.wallet_address() == self.wallet_data.address)
    }

    pub fn create_nano_pay(
        &self,
        recipient_address: &str,
        fee: i64,
        duration: u64,
    ) -> Result<NanoPay, String> {
        NanoPay::new(
            wallet_config_to_rpc_config(&self.config),
            self.clone(),
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
            self.address()
        } else {
            recipient_address.into()
        };
        NanoPayClaimer::new(
            wallet_config_to_rpc_config(&self.config),
            &recipient_address,
            claim_interval_ms,
            min_flush_amount,
        )
    }

    pub fn sign_transaction(&self, tx: &mut Transaction) {
        let ct = create_signature_program_context(self.public_key());
        let signature = sign(tx, self.private_key());
        tx.set_programs(vec![Program::new(&ct, &signature)]);
    }

    pub async fn nonce(&self, tx_pool: bool) -> Result<u64, String> {
        self.nonce_by_address(&self.address(), tx_pool).await
    }

    pub async fn nonce_by_address(&self, address: &str, tx_pool: bool) -> Result<u64, String> {
        get_nonce(address, tx_pool, wallet_config_to_rpc_config(&self.config)).await
    }

    pub async fn balance(&self) -> Result<i64, String> {
        self.balance_by_address(&self.address()).await
    }

    pub async fn balance_by_address(&self, address: &str) -> Result<i64, String> {
        get_balance(address, wallet_config_to_rpc_config(&self.config)).await
    }

    pub async fn height(&self) -> Result<u64, String> {
        get_height(wallet_config_to_rpc_config(&self.config)).await
    }

    pub async fn subscribers(
        &self,
        topic: &str,
        offset: u32,
        limit: u32,
        meta: bool,
        tx_pool: bool,
    ) -> Result<Subscribers, String> {
        get_subscribers(
            topic,
            offset,
            limit,
            meta,
            tx_pool,
            wallet_config_to_rpc_config(&self.config),
        )
        .await
    }

    pub async fn subscription(
        &self,
        topic: &str,
        subscriber: &str,
    ) -> Result<Subscription, String> {
        get_subscription(topic, subscriber, wallet_config_to_rpc_config(&self.config)).await
    }

    pub async fn suscribers_count(
        &self,
        topic: &str,
        subscriber_hash_prefix: &[u8],
    ) -> Result<u32, String> {
        get_subscribers_count(
            topic,
            subscriber_hash_prefix,
            wallet_config_to_rpc_config(&self.config),
        )
        .await
    }

    pub async fn registrant(&self, name: &str) -> Result<Registrant, String> {
        get_registrant(name, wallet_config_to_rpc_config(&self.config)).await
    }

    pub async fn send_raw_transaction(&self, txn: &Transaction) -> Result<String, String> {
        send_raw_transaction(txn, wallet_config_to_rpc_config(&self.config)).await
    }

    pub async fn transfer(
        &self,
        address: &str,
        amount: i64,
        config: TransactionConfig,
    ) -> Result<String, String> {
        let sender = create_program_hash(self.public_key());
        let recipient = to_script_hash(address)?;

        let nonce = if config.nonce > 0 {
            config.nonce
        } else {
            self.nonce(true).await?
        };

        let mut tx =
            Transaction::new_transfer_asset(&sender, &recipient, nonce, amount, config.fee);

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }

    pub async fn register_name(
        &self,
        name: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
        let nonce = if config.nonce > 0 {
            config.nonce
        } else {
            self.nonce(true).await?
        };

        let mut tx = Transaction::new_register_name(
            self.public_key(),
            name,
            nonce,
            MIN_NAME_REGISTRATION_FEE,
            config.fee,
        );

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }

    pub async fn transfer_name(
        &self,
        name: &str,
        recipient_public_key: &[u8],
        config: TransactionConfig,
    ) -> Result<String, String> {
        let nonce = if config.nonce > 0 {
            config.nonce
        } else {
            self.nonce(true).await?
        };

        let mut tx = Transaction::new_transfer_name(
            self.public_key(),
            recipient_public_key,
            name,
            nonce,
            config.fee,
        );

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }

    pub async fn delete_name(
        &self,
        name: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
        let nonce = if config.nonce > 0 {
            config.nonce
        } else {
            self.nonce(true).await?
        };

        let mut tx = Transaction::new_delete_name(self.public_key(), name, nonce, config.fee);

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }

    pub async fn subscribe(
        &self,
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
        let nonce = if config.nonce > 0 {
            config.nonce
        } else {
            self.nonce(true).await?
        };

        let mut tx = Transaction::new_subscribe(
            self.public_key(),
            identifier,
            topic,
            duration,
            meta,
            nonce,
            config.fee,
        );

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }

    pub async fn unsubscribe(
        &self,
        identifier: &str,
        topic: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
        let nonce = if config.nonce > 0 {
            config.nonce
        } else {
            self.nonce(true).await?
        };

        let mut tx =
            Transaction::new_unsubscribe(self.public_key(), identifier, topic, nonce, config.fee);

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }
}

impl AccountHolder for Wallet {
    fn account(&self) -> &Account {
        &self.account
    }

    fn seed(&self) -> [u8; SEED_LEN] {
        self.account.seed()
    }

    fn address(&self) -> String {
        self.account.wallet_address()
    }

    fn program_hash(&self) -> &[u8] {
        self.account.program_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::string_to_amount;

    #[test]
    fn new_seed() {
        let mut seed = [0; 32];
        seed[4] = 5;
        seed[16] = 212;
        let account = Account::new(&seed);
        assert!(account.is_ok());
        let account = account.unwrap();
        let public_key = account.public_key().to_vec();
        let wallet = Wallet::new(
            account,
            WalletConfig {
                password: "password".into(),
                ..WalletConfig::default()
            },
        );
        assert!(wallet.is_ok());
        let wallet = wallet.unwrap();
        assert_eq!(public_key, wallet.public_key());
        assert_eq!(seed.to_vec(), wallet.seed());
    }

    #[test]
    fn new_random() {
        let account = Account::random();
        assert!(account.is_ok());
        let account = account.unwrap();
        let public_key = account.public_key().to_vec();
        let seed = account.seed().to_vec();
        let wallet = Wallet::new(
            account,
            WalletConfig {
                password: "password".into(),
                ..WalletConfig::default()
            },
        );
        assert!(wallet.is_ok());
        let wallet = wallet.unwrap();
        assert_eq!(public_key, wallet.public_key());
        assert_eq!(seed, wallet.seed());
    }

    #[test]
    fn json() {
        let account = Account::random();
        assert!(account.is_ok());
        let account = account.unwrap();
        let wallet = Wallet::new(
            account,
            WalletConfig {
                password: "password".into(),
                ..WalletConfig::default()
            },
        );
        assert!(wallet.is_ok());
        let wallet = wallet.unwrap();

        let wallet_json = wallet.to_json();
        let wallet2 = Wallet::from_json(
            &wallet_json,
            WalletConfig {
                password: "password".into(),
                ..WalletConfig::default()
            },
        );
        assert!(wallet2.is_ok());
        let wallet2 = wallet2.unwrap();
        assert_eq!(wallet.public_key(), wallet2.public_key());
        assert_eq!(wallet.private_key(), wallet2.private_key());
        assert_eq!(wallet.seed(), wallet2.seed());
    }

    #[test]
    fn verify_password() {
        let account = Account::random();
        assert!(account.is_ok());
        let account = account.unwrap();
        let wallet = Wallet::new(
            account,
            WalletConfig {
                password: "42".into(),
                scrypt: ScryptConfig {
                    log_n: 10,
                    ..ScryptConfig::default()
                },
                ..WalletConfig::default()
            },
        );
        assert!(wallet.is_ok());
        let wallet = wallet.unwrap();

        assert_eq!(wallet.verify_password("42"), Ok(true));
        assert_eq!(wallet.verify_password("233"), Ok(false));
    }

    #[test]
    fn verify_address() {
        let account = Account::random();
        assert!(account.is_ok());
        let account = account.unwrap();
        let wallet = Wallet::new(
            account,
            WalletConfig {
                password: "42".into(),
                ..WalletConfig::default()
            },
        );
        assert!(wallet.is_ok());
        let wallet = wallet.unwrap();

        let address = wallet.address();
        println!("{:?}", address);
        assert_eq!(Wallet::verify_address(&address), true);
        assert_eq!(Wallet::verify_address(&address[1..4]), false);
        assert_eq!(
            Wallet::verify_address(&address[0..address.len() - 1]),
            false
        );
    }

    #[tokio::test]
    async fn nonce() {
        let account = Account::random();
        assert!(account.is_ok());
        let account = account.unwrap();
        let wallet = Wallet::new(
            account,
            WalletConfig {
                password: "password".into(),
                ..WalletConfig::default()
            },
        );
        assert!(wallet.is_ok());
        let wallet = wallet.unwrap();

        let nonce = wallet.nonce(true).await;
        assert_eq!(nonce, Ok(0));
    }

    #[tokio::test]
    async fn balance() {
        let account = Account::random();
        assert!(account.is_ok());
        let account = account.unwrap();
        let wallet = Wallet::new(
            account,
            WalletConfig {
                password: "password".into(),
                ..WalletConfig::default()
            },
        );
        assert!(wallet.is_ok());
        let wallet = wallet.unwrap();

        let balance = wallet.balance().await;
        assert_eq!(balance, Ok(0));
    }

    #[tokio::test]
    async fn signer_rpc_methods() {
        let account = Account::random();
        assert!(account.is_ok());
        let account = account.unwrap();
        let wallet = Wallet::new(
            account,
            WalletConfig {
                password: "password".into(),
                ..WalletConfig::default()
            },
        );
        assert!(wallet.is_ok());
        let wallet = wallet.unwrap();

        let res = wallet
            .transfer(
                &wallet.address(),
                string_to_amount("100").unwrap(),
                TransactionConfig::default(),
            )
            .await;
        println!("{:?}", res);
        assert!(res.is_ok());

        let res = wallet
            .register_name("somename", TransactionConfig::default())
            .await;
        println!("{:?}", res);
        assert!(res.is_ok());

        let res = wallet
            .transfer_name(
                "somename",
                wallet.public_key(),
                TransactionConfig::default(),
            )
            .await;
        println!("{:?}", res);
        assert!(res.is_ok());

        let res = wallet
            .delete_name("somename", TransactionConfig::default())
            .await;
        println!("{:?}", res);
        assert!(res.is_ok());

        let res = wallet
            .subscribe(
                "identifier",
                "topic",
                10,
                "meta",
                TransactionConfig::default(),
            )
            .await;
        println!("{:?}", res);
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn nano_pay() {
        let account = Account::random();
        assert!(account.is_ok());
        let account = account.unwrap();
        let wallet = Wallet::new(
            account,
            WalletConfig {
                password: "password".into(),
                ..WalletConfig::default()
            },
        );
        assert!(wallet.is_ok());
        let wallet = wallet.unwrap();

        let np = wallet.create_nano_pay(&wallet.address(), string_to_amount("0").unwrap(), 200);
        assert!(np.is_ok());
        let mut np = np.unwrap();

        let res = np.increment_amount(string_to_amount("100").unwrap()).await;
        println!("{:?}", res);
        assert!(res.is_ok());
    }
}
