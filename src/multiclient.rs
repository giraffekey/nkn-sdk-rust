use crate::rpc::{RPCClient, Registrant, SignerRPCClient, Subscribers, Subscription};
use crate::transaction::{Transaction, TransactionConfig};

use async_trait::async_trait;

pub struct MultiClientConfig {}

pub struct MultiClient {}

#[async_trait]
impl RPCClient for MultiClient {
    async fn nonce(&self, tx_pool: bool) -> u64 {
        todo!()
    }

    async fn nonce_by_address(&self, address: &str, tx_pool: bool) -> u64 {
        todo!()
    }

    async fn balance(&self) -> u64 {
        todo!()
    }

    async fn balance_by_address(&self, address: &str) -> u64 {
        todo!()
    }

    async fn height(&self) -> u32 {
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
    fn sign_transaction(&self, tx: &mut Transaction) {
        todo!()
    }

    fn transfer(&self, address: &str, amount: u64, config: TransactionConfig) -> String {
        todo!()
    }

    fn register_name(&self, name: &str, config: TransactionConfig) -> String {
        todo!()
    }

    fn transfer_name(
        &self,
        name: &str,
        recipient_public_key: &[u8],
        config: TransactionConfig,
    ) -> String {
        todo!()
    }

    fn delete_name(&self, name: &str, config: TransactionConfig) -> String {
        todo!()
    }

    fn subscribe(
        &self,
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        config: TransactionConfig,
    ) -> String {
        todo!()
    }

    fn unsubscribe(&self, identifier: &str, topic: &str, config: TransactionConfig) -> String {
        todo!()
    }
}
