use crate::crypto::SEED_LEN;
use crate::rpc::{Registrant, Subscribers, Subscription};
use crate::transaction::{Transaction, TransactionConfig};
use crate::vault::{Account, AccountHolder};

pub struct MultiClientConfig {}

pub struct MultiClient {}

impl AccountHolder for MultiClient {
    fn account(&self) -> &Account {
        todo!()
    }

    fn seed(&self) -> [u8; SEED_LEN] {
        todo!()
    }

    fn address(&self) -> String {
        todo!()
    }

    fn program_hash(&self) -> &[u8] {
        todo!()
    }
}
