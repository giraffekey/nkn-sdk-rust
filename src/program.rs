use crate::crypto::{ripemd160_hash, sha256_hash};

use base58::ToBase58;
use serde::{Deserialize, Serialize};

const SIGNATURE: u8 = 0;
const CHECKSIG: u8 = 0xAC;
// FOOLPROOFPREFIX used for fool-proof prefix
// base58.BitcoinEncoding[21] = 'N', base58.BitcoinEncoding[18] = 'K'
// 33 = len(base58.Encode( (2**192).Bytes() )),  192 = 8bit * (UINT160SIZE + SHA256CHKSUM)
// ((21 * 58**35) + (18 * 58**34) + (21 * 58**33)) >> 192 = 0x02b824
const FOOL_PROOF_PREFIX: u64 = 0x02b824 + 1; // +1 for avoid affected by lower 192bits shift-add
const SHA256_CHECKSUM: usize = 4;

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
    data.extend_from_slice(&FOOL_PROOF_PREFIX.to_ne_bytes());
    data.extend_from_slice(hash);

    let temp = sha256_hash(&data);
    let temp = sha256_hash(&temp);
    data.extend_from_slice(&temp[0..SHA256_CHECKSUM]);

    data.to_base58()
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
