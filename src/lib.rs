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
pub use nanopay::{NanoPay, NanoPayClaimer};
pub use rpc::{get_balance, rpc_call, Node, RPCConfig, Registrant, Subscription};
pub use transaction::{Transaction, TransactionConfig};
pub use util::{amount_to_string, string_to_amount, Account, Subscribers};
pub use wallet::{Wallet, WalletConfig};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
