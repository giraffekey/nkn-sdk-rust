use crate::rpc::{RPCClient, Registrant, SignerRPCClient, Subscribers, Subscription};
use crate::transaction::{Transaction, TransactionConfig};

pub struct MultiClientConfig {}

pub struct MultiClient {}

impl RPCClient for MultiClient {
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

    fn suscribers_count(&self, topic: &str, subscriber_hash_prefix: &[u8]) -> u32 {
        todo!()
    }

    fn registrant(&self, name: &str) -> Registrant {
        todo!()
    }

    fn send_raw_transaction(&self, txn: Transaction) -> String {
        todo!()
    }
}

impl SignerRPCClient for MultiClient {
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
