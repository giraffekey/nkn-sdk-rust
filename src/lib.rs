mod client;
mod constant;
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
pub use rpc::{Node, Registrant, Subscription};
pub use transaction::{Transaction, TransactionConfig};
pub use util::{Account, Subscribers};
pub use wallet::{Wallet, WalletConfig};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
