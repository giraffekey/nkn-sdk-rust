use crate::crypto::{ed25519_keypair, ed25519_seed_from_private_key};
use crate::program::{code_hash_to_address, create_program_hash};
use crate::signature::Signer;

use rand::Rng;

#[derive(Debug, Clone)]
pub struct Account {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    program_hash: Vec<u8>,
}

impl Account {
    pub fn new(seed: &[u8]) -> Result<Self, String> {
        if seed.len() != 32 {
            return Err("Invalid seed length".into());
        }

        let (private_key, public_key) = ed25519_keypair(seed);
        let program_hash = create_program_hash(&public_key);

        Ok(Self {
            private_key,
            public_key,
            program_hash,
        })
    }

    pub fn random() -> Result<Self, String> {
        let mut rng = rand::thread_rng();
        let mut seed = [0; 32];
        rng.fill(&mut seed);
        Self::new(&seed)
    }

    pub fn seed(&self) -> Vec<u8> {
        ed25519_seed_from_private_key(&self.private_key)
    }

    pub fn program_hash(&self) -> &[u8] {
        &self.program_hash
    }

    pub fn wallet_address(&self) -> String {
        code_hash_to_address(&self.program_hash)
    }
}

impl Signer for Account {
    fn private_key(&self) -> &[u8] {
        &self.private_key
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

pub fn string_to_amount(s: &str) -> u64 {
    todo!()
}

pub fn amount_to_string(amount: u64) -> String {
    todo!()
}

pub trait AccountHolder {
    fn account(&self) -> &Account;
    fn public_key(&self) -> &[u8];
    fn private_key(&self) -> &[u8];
    fn seed(&self) -> Vec<u8>;
    fn address(&self) -> String;
    fn program_hash(&self) -> &[u8];
}
