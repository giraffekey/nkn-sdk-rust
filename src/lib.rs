mod client;
mod constant;
mod crypto;
mod message;
mod multiclient;
mod nanopay;
mod rpc;
mod transaction;
mod util;
mod vault;

pub use client::{Client, ClientConfig};
pub use message::{Message, MessageConfig};
pub use multiclient::{MultiClient, MultiClientConfig};
pub use nanopay::{NanoPay, NanoPayClaimer};
pub use rpc::{
    get_balance, get_node_state, get_registrant, get_subscription, get_ws_address, get_wss_address,
    measure_rpc_server, rpc_call, Node, RPCClient, RPCConfig, Registrant, SignerRPCClient,
    Subscription,
};
pub use transaction::{Transaction, TransactionConfig};
pub use util::{get_subscribers, Subscribers};
pub use vault::account::{amount_to_string, string_to_amount, Account};
pub use vault::wallet::{Wallet, WalletConfig};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
