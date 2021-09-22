mod client;
mod constant;
mod crypto;
mod message;
mod multiclient;
mod nanopay;
mod rpc;
mod transaction;
mod util;
mod wallet;

pub use client::{Client, ClientConfig};
pub use message::{Message, MessageConfig};
pub use multiclient::{MultiClient, MultiClientConfig};
pub use nanopay::{NanoPay, NanoPayClaimer};
pub use rpc::{
    get_balance, get_node_state, get_registrant, get_subscription, get_ws_address, get_wss_address,
    rpc_call, Node, RPCClient, RPCConfig, Registrant, SignerRPCClient, Subscription,
};
pub use transaction::{Transaction, TransactionConfig};
pub use util::{
    amount_to_string, get_subscribers, measure_rpc_server, string_to_amount, Account, Subscribers,
};
pub use wallet::{Wallet, WalletConfig};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
