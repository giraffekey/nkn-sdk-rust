use crate::crypto::{ed25519_sign, ed25519_verify, sha256_hash, SHA256_LEN, SIGNATURE_LEN};
use crate::program::Program;
use crate::transaction::Transaction;

pub trait SignableData {
    fn program_hashes(&self) -> Vec<Vec<u8>>;
    fn programs(&self) -> &[Program];
    fn set_programs(&mut self, programs: Vec<Program>);
    fn serialize_unsigned(&self) -> Vec<u8>;
}

pub fn get_hash_data<D: SignableData>(data: &D) -> Vec<u8> {
    data.serialize_unsigned()
}

pub fn get_hash_for_signing<D: SignableData>(data: &D) -> [u8; SHA256_LEN] {
    sha256_hash(&get_hash_data(data))
}

pub fn sign<D: SignableData>(data: &D, private_key: &[u8]) -> [u8; SIGNATURE_LEN] {
    ed25519_sign(&get_hash_for_signing(data), private_key)
}

pub fn verify_signable_data<D: SignableData>(data: &D) -> bool {
    todo!()
}

pub fn verify_signature<D: SignableData>(data: &D, public_key: &[u8], signature: &[u8]) -> bool {
    ed25519_verify(&get_hash_for_signing(data), public_key, signature)
}
