use crate::vault::ScryptConfig;

use crypto::aes::{cbc_decryptor, cbc_encryptor, KeySize};
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::digest::Digest;
use crypto::ed25519;
use crypto::ripemd160::Ripemd160;
use crypto::scrypt::{scrypt, ScryptParams};
use crypto::sha3::Sha3;
use std::convert::TryInto;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const PRIVATE_KEY_LEN: usize = 64;
pub const SIGNATURE_LEN: usize = 64;
pub const SHARED_KEY_LEN: usize = 32;
pub const SEED_LEN: usize = 32;
pub const SHA256_LEN: usize = 32;
pub const RIPEMD160_LEN: usize = 20;
pub const IV_LEN: usize = 16;
pub const SCRYPT_KEY_LEN: usize = 32;

pub fn ed25519_keypair(seed: &[u8]) -> ([u8; PRIVATE_KEY_LEN], [u8; PUBLIC_KEY_LEN]) {
    ed25519::keypair(seed)
}

pub fn ed25519_sign(data: &[u8], private_key: &[u8]) -> [u8; SIGNATURE_LEN] {
    ed25519::signature(data, private_key)
}

pub fn ed25519_verify(data: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    ed25519::verify(data, public_key, signature)
}

pub fn ed25519_exchange(public_key: &[u8], private_key: &[u8]) -> [u8; SHARED_KEY_LEN] {
    ed25519::exchange(public_key, private_key)
}

pub fn sha256_hash(input: &[u8]) -> [u8; SHA256_LEN] {
    let mut hasher = Sha3::sha3_256();
    hasher.input(input);
    let mut hash = [0u8; 32];
    hasher.result(&mut hash);
    hash
}

pub fn sha512_hash(input: &[u8]) -> [u8; SHA256_LEN] {
    let mut hasher = Sha3::sha3_512();
    hasher.input(input);
    let mut hash = [0u8; 32];
    hasher.result(&mut hash);
    hash
}

pub fn ripemd160_hash(input: &[u8]) -> [u8; RIPEMD160_LEN] {
    let mut md = Ripemd160::new();
    md.input(&input);
    let mut hash = [0u8; 20];
    md.result(&mut hash);
    hash
}

pub fn scrypt_kdf(input: &[u8], config: &ScryptConfig) -> [u8; SCRYPT_KEY_LEN] {
    let mut output = [0u8; 32];
    let params = ScryptParams::new(config.log_n, config.r, config.p);
    scrypt(input, &config.salt, &params, &mut output);
    output
}

pub fn aes_encrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut encryptor = cbc_encryptor(KeySize::KeySize256, key, iv, NoPadding);
    let mut input_buf = RefReadBuffer::new(input);
    let mut output = vec![0u8; input.len()];
    let mut output_buf = RefWriteBuffer::new(&mut output);
    encryptor
        .encrypt(&mut input_buf, &mut output_buf, true)
        .unwrap();
    output
}

pub fn aes_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut decryptor = cbc_decryptor(KeySize::KeySize256, key, iv, NoPadding);
    let mut input_buf = RefReadBuffer::new(input);
    let mut output = vec![0u8; input.len()];
    let mut output_buf = RefWriteBuffer::new(&mut output);
    decryptor
        .decrypt(&mut input_buf, &mut output_buf, true)
        .unwrap();
    output
}

pub fn ed25519_private_key_to_curve25519_private_key(private_key: &[u8]) -> [u8; SHARED_KEY_LEN] {
    let mut key = sha512_hash(&private_key[..32]);
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

pub fn ed25519_public_key_to_curve25519_public_key(public_key: &[u8]) -> [u8; PUBLIC_KEY_LEN] {
    todo!()
}

pub fn ed25519_seed_from_private_key(private_key: &[u8]) -> [u8; SEED_LEN] {
    private_key[..32].try_into().unwrap()
}
