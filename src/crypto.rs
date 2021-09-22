use crate::constant::{CHECKSIG, FOOL_PROOF_PREFIX, SHA256_CHECKSUM};

use base58::ToBase58;
use crypto::digest::Digest;
use crypto::ed25519;
use crypto::ripemd160::Ripemd160;
use crypto::sha3::Sha3;

pub fn keypair(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (private_key, public_key) = ed25519::keypair(seed);
    (private_key.to_vec(), public_key.to_vec())
}

pub fn sha256_hash(input: &[u8]) -> Vec<u8> {
	let mut hasher = Sha3::sha3_256();
    hasher.input(input);
    let mut hash = [0u8; 32];
    hasher.result(&mut hash);
    hash.to_vec()
}

pub fn ripemd160_hash(input: &[u8]) -> Vec<u8> {
	let mut md = Ripemd160::new();
    md.input(&input);
    let mut hash = [0u8; 20];
    md.result(&mut hash);
    hash.to_vec()
}

// CODE: len(publickey) + publickey + CHECKSIG
pub fn create_signature_program_code(public_key: &[u8]) -> Vec<u8> {
    let mut code = Vec::new();
    code.push(public_key.len() as u8);
    code.extend_from_slice(public_key);
    code.push(CHECKSIG);
    code
}

pub fn to_code_hash(code: &[u8]) -> Vec<u8> {
    let hash = sha256_hash(code);
    ripemd160_hash(&hash)
}

pub fn code_hash_to_address(hash: &[u8]) -> String {
	let mut data = Vec::new();
	data.extend_from_slice(&FOOL_PROOF_PREFIX.to_ne_bytes());
	data.extend_from_slice(hash);

	let temp = sha256_hash(&data);
	let temp = sha256_hash(&temp);
	data.extend_from_slice(&temp[0..SHA256_CHECKSUM]);

	data.to_base58()
}

pub fn create_program_hash(public_key: &[u8]) -> Vec<u8> {
    let code = create_program_hash(public_key);
    to_code_hash(&code)
}
