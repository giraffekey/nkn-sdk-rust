use crypto::ed25519;
use rand::Rng;
use std::collections::HashMap;

pub struct Account {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    seed: Vec<u8>, // until a way to get seed from private key is implemented
}

impl Account {
    pub fn new(seed: &[u8]) -> Result<Self, String> {
        if seed.len() != 32 {
            return Err("Invalid seed length".into());
        }

        let (private_key, public_key) = ed25519::keypair(seed);

        Ok(Self {
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            seed: seed.to_vec(),
        })
    }

    pub fn new_random<R: Rng + ?Sized>(rng: &mut R) -> Result<Self, String> {
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
