use crate::crypto::{ripemd160_hash, sha256_hash};

use base58::{FromBase58, ToBase58};
use serde::{Deserialize, Serialize};

const SIGNATURE: u8 = 0;
const CHECKSIG: u8 = 0xAC;
const ADDRESS_GEN_PREFIX: &[u8] = &[0x02, 0xb8, 0x25];
const CHECKSUM_LEN: usize = 4;

// CODE: len(publickey) + publickey + CHECKSIG
pub fn create_signature_program_code(public_key: &[u8]) -> Vec<u8> {
    let mut code = Vec::new();
    code.push(public_key.len() as u8);
    code.extend_from_slice(public_key);
    code.push(CHECKSIG);
    code
}

pub fn to_code_hash(code: &[u8]) -> Vec<u8> {
    ripemd160_hash(&sha256_hash(code))
}

pub fn create_program_hash(public_key: &[u8]) -> Vec<u8> {
    to_code_hash(&create_signature_program_code(public_key))
}

pub fn code_hash_to_address(hash: &[u8]) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(ADDRESS_GEN_PREFIX);
    data.extend_from_slice(hash);

    let temp = sha256_hash(&data);
    let temp = sha256_hash(&temp);
    data.extend_from_slice(&temp[0..CHECKSUM_LEN]);

    data.to_base58()
}

pub fn to_script_hash(address: &str) -> Vec<u8> {
    let hash = address.from_base58().unwrap();
    hash[3..23].to_vec()
}

pub struct ProgramContext {
    code: Vec<u8>,
    parameters: Vec<u8>,
    program_hash: Vec<u8>,
    owner_public_key_hash: Vec<u8>,
}

pub fn create_signature_program_context(owner_public_key: &[u8]) -> ProgramContext {
    let code = create_signature_program_code(owner_public_key);
    let owner_public_key_hash = to_code_hash(owner_public_key);
    let program_hash = to_code_hash(&owner_public_key_hash);

    ProgramContext {
        code,
        parameters: vec![SIGNATURE],
        program_hash,
        owner_public_key_hash,
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Program {
    code: Vec<u8>,
    parameter: Vec<u8>,
}

impl Program {
    pub fn new(ct: &ProgramContext, signature: &[u8]) -> Self {
        let mut parameter = Vec::new();
        parameter.push(signature.len() as u8);
        parameter.extend_from_slice(signature);

        Self {
            code: ct.code.clone(),
            parameter,
        }
    }
}
