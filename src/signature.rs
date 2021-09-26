use crate::crypto::{ed25519_sign, sha256_hash};
use crate::program::Program;

pub trait SignableData {
    fn program_hashes(&self) -> Vec<Vec<u8>>;
    fn programs(&self) -> &[Program];
    fn set_programs(&mut self, programs: Vec<Program>);
    fn serialize_unsigned(&self) -> Vec<u8>;
}

pub fn get_hash_data<D: SignableData>(data: &D) -> Vec<u8> {
    data.serialize_unsigned()
}

pub fn get_hash_for_signing<D: SignableData>(data: &D) -> Vec<u8> {
    sha256_hash(&get_hash_data(data))
}

pub fn sign<D: SignableData>(data: &D, private_key: &[u8]) -> Vec<u8> {
    ed25519_sign(&get_hash_for_signing(data), private_key)
}

pub trait Signer {
    fn private_key(&self) -> &[u8];
    fn public_key(&self) -> &[u8];
}

pub fn sign_by_signer<D: SignableData, S: Signer>(data: &D, signer: &S) -> Vec<u8> {
    sign(data, signer.private_key())
}
