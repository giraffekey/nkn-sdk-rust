use crate::client::ClientConfig;
use crate::rpc::RPCConfig;
use crate::vault::WalletConfig;

pub fn wallet_config_to_rpc_config(config: &WalletConfig) -> RPCConfig {
    RPCConfig {
        rpc_server_address: config.rpc_server_address.clone(),
        rpc_timeout: config.rpc_timeout,
        rpc_concurrency: config.rpc_concurrency,
    }
}

pub fn client_config_to_rpc_config(config: &ClientConfig) -> RPCConfig {
    RPCConfig {
        rpc_server_address: config.rpc_server_address.clone(),
        rpc_timeout: config.rpc_timeout,
        rpc_concurrency: config.rpc_concurrency,
    }
}
