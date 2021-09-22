use crate::crypto::{aes_encrypt, ed25519_seed_from_private_key, scrypt_kdf, sha256_hash, ScryptConfig};
use crate::Account;

const WALLET_VERSION: u32 = 2;
const IV_LEN: usize = 16;

fn get_password_key(
    password: &[u8],
    version: u32,
    scrypt_config: &ScryptConfig,
) -> Result<Vec<u8>, String> {
    match version {
        1 => Ok(sha256_hash(&sha256_hash(password))),
        2 => Ok(scrypt_kdf(password, scrypt_config)),
        _ => Err("Incorrect wallet version".into()),
    }
}

pub struct WalletData {
    pub version: u32,
    pub iv: Vec<u8>,
    pub master_key_cipher: Vec<u8>,
    pub seed_cipher: Vec<u8>,
    pub address: String,
    pub scrypt_config: ScryptConfig,
}

impl WalletData {
    pub fn new(
        account: &Account,
        password: &str,
        master_key: &[u8],
        iv: &[u8],
        scrypt_config: ScryptConfig,
    ) -> Self {
        let password_key =
            get_password_key(password.as_bytes(), WALLET_VERSION, &scrypt_config).unwrap();
        let seed = ed25519_seed_from_private_key(account.private_key());

        let master_key_cipher = aes_encrypt(master_key, &password_key, iv);
        let seed_cipher = aes_encrypt(&seed, &password_key, iv);

        Self {
            version: WALLET_VERSION,
            iv: iv.to_vec(),
            master_key_cipher,
            seed_cipher,
            address: account.wallet_address(),
            scrypt_config,
        }
    }
}
