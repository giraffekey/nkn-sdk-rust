use crate::program::Program;
use crate::signature::SignableData;

use std::convert::TryInto;

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

struct Payload {
    r#type: u32,
    data: Vec<u8>,
}

fn serialize_payload(payload: &Payload) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&payload.r#type.to_ne_bytes());
    bytes.extend_from_slice(&payload.data);
    bytes
}

fn deserialize_payload(bytes: &[u8]) -> Payload {
    let typ = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
    let data = &bytes[4..];

    Payload {
        r#type: typ,
        data: data.to_vec(),
    }
}

struct UnsignedTx {
    payload: Payload,
    nonce: u64,
    fee: u64,
    attributes: Vec<u8>,
}

pub struct Transaction {
    unsigned_tx: UnsignedTx,
    programs: Vec<Program>,
    hash: Vec<u8>,
    size: u32,
    is_signature_verified: bool,
}

impl SignableData for Transaction {
    fn program_hashes(&self) -> Vec<Vec<u8>> {
        todo!()
    }

    fn programs(&self) -> &[Program] {
        &self.programs
    }

    fn set_programs(&mut self, programs: Vec<Program>) {
        self.programs = programs;
    }

    fn serialize_unsigned(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&serialize_payload(&self.unsigned_tx.payload));
        bytes.extend_from_slice(&self.unsigned_tx.nonce.to_ne_bytes());
        bytes.extend_from_slice(&self.unsigned_tx.fee.to_ne_bytes());
        bytes.extend_from_slice(&self.unsigned_tx.attributes);
        bytes
    }
}
