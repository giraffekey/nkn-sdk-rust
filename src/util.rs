use crypto::ed25519;
use rand::Rng;
use std::collections::HashMap;

pub struct Account {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    seed: Vec<u8>, // until a way to get seed from private key is implemented
}

impl Account {
    pub fn new<R: Rng + ?Sized>(rng: &mut R, seed: &[u8]) -> Result<Self, String> {
        if seed.len() != 32 || seed.len() != 0 {
            return Err("Invalid seed length".into());
        }

        let seed = if seed.is_empty() {
            let mut seed = [0; 32];
            rng.fill(&mut seed);
            seed.to_vec()
        } else {
            seed.to_vec()
        };

        let (private_key, public_key) = ed25519::keypair(&seed);

        Ok(Self {
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            seed,
        })
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
