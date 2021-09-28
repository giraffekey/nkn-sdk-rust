use crate::rpc::{RPCClient, Registrant, SignerRPCClient, Subscribers, Subscription};
use crate::transaction::{Transaction, TransactionConfig};

use async_trait::async_trait;

pub struct MultiClientConfig {}

pub struct MultiClient {}

#[async_trait]
impl RPCClient for MultiClient {
    async fn nonce(&self, tx_pool: bool) -> Result<u64, String> {
        todo!()
    }

    async fn nonce_by_address(&self, address: &str, tx_pool: bool) -> Result<u64, String> {
        todo!()
    }

    async fn balance(&self) -> Result<u64, String> {
        todo!()
    }

    async fn balance_by_address(&self, address: &str) -> Result<u64, String> {
        todo!()
    }

    async fn height(&self) -> Result<u32, String> {
        todo!()
    }

    async fn subscribers(
        &self,
        topic: &str,
        offset: u32,
        limit: u32,
        meta: bool,
        tx_pool: bool,
    ) -> Result<Subscribers, String> {
        todo!()
    }

    async fn subscription(&self, topic: &str, subscriber: &str) -> Result<Subscription, String> {
        todo!()
    }

    async fn suscribers_count(
        &self,
        topic: &str,
        subscriber_hash_prefix: &[u8],
    ) -> Result<u32, String> {
        todo!()
    }

    async fn registrant(&self, name: &str) -> Result<Registrant, String> {
        todo!()
    }

    async fn send_raw_transaction(&self, txn: Transaction) -> Result<String, String> {
        todo!()
    }
}

#[async_trait]
impl SignerRPCClient for MultiClient {
    fn sign_transaction(&self, tx: &mut Transaction) {
        todo!()
    }

    async fn transfer(
        &self,
        address: &str,
        amount: u64,
        config: TransactionConfig,
    ) -> Result<String, String> {
        todo!()
    }

    async fn register_name(&self, name: &str, config: TransactionConfig) -> Result<String, String> {
        todo!()
    }

    async fn transfer_name(
        &self,
        name: &str,
        recipient_public_key: &[u8],
        config: TransactionConfig,
    ) -> Result<String, String> {
        todo!()
    }

    async fn delete_name(&self, name: &str, config: TransactionConfig) -> Result<String, String> {
        todo!()
    }

    async fn subscribe(
        &self,
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
        todo!()
    }

    async fn unsubscribe(
        &self,
        identifier: &str,
        topic: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
        todo!()
    }
}
