use crate::vault::ScryptConfig;

use crypto::aes::{cbc_decryptor, cbc_encryptor, KeySize};
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::digest::Digest;
use crypto::ed25519;
use crypto::ripemd160::Ripemd160;
use crypto::scrypt::{scrypt, ScryptParams};
use crypto::sha3::Sha3;

pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
pub const ED25519_PRIVATE_KEY_LENGTH: usize = 64;
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

pub fn ed25519_keypair(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (private_key, public_key) = ed25519::keypair(seed);
    (private_key.to_vec(), public_key.to_vec())
}

pub fn ed25519_sign(data: &[u8], private_key: &[u8]) -> Vec<u8> {
    ed25519::signature(data, private_key).to_vec()
}

pub fn ed25519_verify(data: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    ed25519::verify(data, public_key, signature)
}

pub fn sha256_hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3::sha3_256();
    hasher.input(input);
    let mut hash = [0u8; 32];
    hasher.result(&mut hash);
    hash.to_vec()
}

pub fn sha512_hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3::sha3_512();
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

pub fn scrypt_kdf(input: &[u8], config: &ScryptConfig) -> Vec<u8> {
    let mut output = [0u8; 32];
    let params = ScryptParams::new(config.log_n, config.r, config.p);
    scrypt(input, &config.salt, &params, &mut output);
    output.to_vec()
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

pub fn ed25519_private_key_to_curve25519_private_key(private_key: &[u8]) -> Vec<u8> {
    let mut key = sha512_hash(&private_key[..32]);
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

pub fn ed25519_seed_from_private_key(private_key: &[u8]) -> Vec<u8> {
    private_key[..32].to_vec()
}
