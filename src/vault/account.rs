use crate::crypto::{ed25519_keypair, ripemd160_hash, sha256_hash};

use base58::ToBase58;
use rand::Rng;

const CHECKSIG: u8 = 0xAC;
// FOOLPROOFPREFIX used for fool-proof prefix
// base58.BitcoinEncoding[21] = 'N', base58.BitcoinEncoding[18] = 'K'
// 33 = len(base58.Encode( (2**192).Bytes() )),  192 = 8bit * (UINT160SIZE + SHA256CHKSUM)
// ((21 * 58**35) + (18 * 58**34) + (21 * 58**33)) >> 192 = 0x02b824
const FOOL_PROOF_PREFIX: u64 = 0x02b824 + 1; // +1 for avoid affected by lower 192bits shift-add
const SHA256_CHECKSUM: usize = 4;

// CODE: len(publickey) + publickey + CHECKSIG
fn create_signature_program_code(public_key: &[u8]) -> Vec<u8> {
    let mut code = Vec::new();
    code.push(public_key.len() as u8);
    code.extend_from_slice(public_key);
    code.push(CHECKSIG);
    code
}

fn to_code_hash(code: &[u8]) -> Vec<u8> {
    ripemd160_hash(&sha256_hash(code))
}

fn create_program_hash(public_key: &[u8]) -> Vec<u8> {
    to_code_hash(&create_signature_program_code(public_key))
}

fn code_hash_to_address(hash: &[u8]) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(&FOOL_PROOF_PREFIX.to_ne_bytes());
    data.extend_from_slice(hash);

    let temp = sha256_hash(&data);
    let temp = sha256_hash(&temp);
    data.extend_from_slice(&temp[0..SHA256_CHECKSUM]);

    data.to_base58()
}

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

        let (private_key, public_key) = ed25519_keypair(seed);
        let program_hash = create_program_hash(&public_key);

        Ok(Self {
            private_key,
            public_key,
            seed: seed.to_vec(),
            program_hash,
        })
    }

    pub fn random<R: Rng + ?Sized>(rng: &mut R) -> Result<Self, String> {
        let mut seed = [0; 32];
        rng.fill(&mut seed);
        Self::new(&seed)
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn private_key(&self) -> &[u8] {
        &self.private_key
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

pub trait AccountHolder {
    fn account(&self) -> &Account;
    fn public_key(&self) -> &[u8];
    fn private_key(&self) -> &[u8];
    fn seed(&self) -> &[u8];
    fn address(&self) -> String;
    fn program_hash(&self) -> &[u8];
}
