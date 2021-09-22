use crate::crypto::{code_hash_to_address, create_program_hash, keypair};
use crate::RPCConfig;

use rand::{thread_rng, Rng};
use std::collections::HashMap;

pub struct Account {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    seed: Vec<u8>, // until a way to get seed from private key is implemented
    program_hash: Vec<u8>,
}

impl Account {
    pub fn new(seed: &[u8]) -> Result<Self, String> {
        if seed.len() != 32 {
            return Err("Invalid seed length".into());
        }

        let (private_key, public_key) = keypair(seed);
        let program_hash = create_program_hash(&public_key);

        Ok(Self {
            private_key,
            public_key,
            seed: seed.to_vec(),
            program_hash,
        })
    }

    pub fn new_random() -> Result<Self, String> {
        let mut rng = thread_rng();
        let mut seed = [0; 32];
        rng.fill(&mut seed);
        Self::new(&seed)
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    pub fn program_hash(&self) -> &[u8] {
        &self.program_hash
    }

    pub fn wallet_address(&self) -> String {
        code_hash_to_address(&self.program_hash)
    }
}

pub fn string_to_amount(s: &str) -> u64 {
    todo!()
}

pub fn amount_to_string(amount: u64) -> String {
    todo!()
}

pub struct Subscribers {
    map: HashMap<String, String>,
    tx_pool_map: HashMap<String, String>,
}

impl Subscribers {
    fn map(&self) -> &HashMap<String, String> {
        &self.map
    }

    fn tx_pool_map(&self) -> &HashMap<String, String> {
        &self.tx_pool_map
    }
}

pub fn get_subscribers(
    topic: &str,
    offset: u32,
    limit: u32,
    meta: bool,
    tx_pool: bool,
    config: RPCConfig,
) -> Subscribers {
    todo!()
}

pub fn measure_rpc_server(rpc_list: &[&str], timeout: u32) -> Vec<String> {
    todo!()
}
