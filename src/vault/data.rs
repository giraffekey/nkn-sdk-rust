use crate::crypto::{
    aes_decrypt, aes_encrypt, ed25519_seed_from_private_key, scrypt_kdf, sha256_hash, IV_LEN,
    SHA256_LEN,
};
use crate::signature::Signer;
use crate::vault::{Account, ScryptConfig, SCRYPT_SALT_LEN};

use serde::{Deserialize, Serialize};

pub const WALLET_VERSION: u32 = 2;
pub const MIN_COMPATIBLE_WALLET_VERSION: u32 = 1;
pub const MAX_COMPATIBLE_WALLET_VERSION: u32 = 2;

fn get_password_key(
    password: &[u8],
    version: u32,
    config: &ScryptConfig,
) -> Result<[u8; SHA256_LEN], String> {
    match version {
        1 => Ok(sha256_hash(&sha256_hash(password))),
        2 => Ok(scrypt_kdf(password, config)),
        _ => Err("Incompatible wallet version".into()),
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScryptConfigEncoded {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    pub salt: String,
}

fn encode_scrypt_config(scrypt: &ScryptConfig) -> ScryptConfigEncoded {
    ScryptConfigEncoded {
        log_n: scrypt.log_n,
        r: scrypt.r,
        p: scrypt.p,
        salt: hex::encode(scrypt.salt),
    }
}

fn decode_scrypt_config(scrypt: &ScryptConfigEncoded) -> ScryptConfig {
    let mut salt = [0u8; SCRYPT_SALT_LEN];
    hex::decode_to_slice(&scrypt.salt, &mut salt).unwrap();

    ScryptConfig {
        log_n: scrypt.log_n,
        r: scrypt.r,
        p: scrypt.p,
        salt,
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WalletData {
    pub version: u32,
    pub iv: String,
    pub masterkey: String,
    pub seedencrypted: String,
    pub address: String,
    pub scrypt: ScryptConfigEncoded,
}

impl WalletData {
    pub fn new(
        account: &Account,
        password: &str,
        master_key: &[u8],
        iv: [u8; IV_LEN],
        scrypt: ScryptConfig,
    ) -> Result<Self, String> {
        let password_key = get_password_key(password.as_bytes(), WALLET_VERSION, &scrypt)?;
        let seed = ed25519_seed_from_private_key(account.private_key());

        let master_key_cipher = aes_encrypt(master_key, &password_key, &iv);
        let seed_cipher = aes_encrypt(&seed, &master_key, &iv);

        let scrypt = encode_scrypt_config(&scrypt);

        Ok(Self {
            version: WALLET_VERSION,
            iv: hex::encode(iv),
            masterkey: hex::encode(master_key_cipher),
            seedencrypted: hex::encode(seed_cipher),
            address: account.wallet_address(),
            scrypt,
        })
    }

    pub fn decrypt_master_key(&self, password: &str) -> Result<Vec<u8>, String> {
        let scrypt = decode_scrypt_config(&self.scrypt);
        let password_key = get_password_key(password.as_bytes(), self.version, &scrypt)?;
        let iv = hex::decode(&self.iv).unwrap();
        let master_key_cipher = hex::decode(&self.masterkey).unwrap();
        Ok(aes_decrypt(&master_key_cipher, &password_key, &iv))
    }

    pub fn decrypt_account(&self, password: &str) -> Result<Account, String> {
        let master_key = self.decrypt_master_key(password)?;
        let iv = hex::decode(&self.iv).unwrap();
        let seed_cipher = hex::decode(&self.seedencrypted).unwrap();
        let seed = aes_decrypt(&seed_cipher, &master_key, &iv);
        Account::new(&seed)
    }
}
