use crate::constant::{DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT};
use crate::Account;

pub struct WalletConfig {
    pub rpc_server_address: Vec<String>,
    pub rpc_timeout: u32,
    pub rpc_concurrency: u32,
    pub password: String,
    pub iv: Vec<u8>,
    pub master_key: Vec<u8>,
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
        }
    }
}

pub struct Wallet<'a> {
    account: &'a Account,
    config: WalletConfig,
}

impl<'a> Wallet<'a> {
    pub fn new(account: &'a Account, config: WalletConfig) -> Self {
        Self { account, config }
    }

    pub fn from_json(json: &str, config: WalletConfig) -> Self {
        todo!()
    }

    pub fn config(&self) -> &WalletConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: WalletConfig) {
        self.config = config
    }

    pub fn account(&self) -> &Account {
        self.account
    }

    pub fn address(&self) -> &str {
        todo!()
    }

    pub fn balance(&self) -> u64 {
        todo!()
    }

    pub fn balance_by_address(&self, address: &str) -> u64 {
        todo!()
    }
}
