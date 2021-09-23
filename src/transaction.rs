#[derive(Debug)]
pub struct TransactionConfig {
    fee: u64,
    nonce: u64,
    attributes: Vec<u8>,
}

impl Default for TransactionConfig {
    fn default() -> Self {
        Self {
            fee: 0,
            nonce: 0,
            attributes: Vec::new(),
        }
    }
}

pub struct Transaction {}
