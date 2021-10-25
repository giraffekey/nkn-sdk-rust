use rand::Rng;

pub const SCRYPT_SALT_LEN: usize = 8;
pub const SCRYPT_LOG_N: u8 = 15;
pub const SCRYPT_R: u32 = 8;
pub const SCRYPT_P: u32 = 1;

#[derive(Debug, Clone)]
pub struct ScryptConfig {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    pub salt: [u8; SCRYPT_SALT_LEN],
}

impl Default for ScryptConfig {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; SCRYPT_SALT_LEN];
        rng.fill(&mut salt);

        Self {
            log_n: SCRYPT_LOG_N,
            r: SCRYPT_R,
            p: SCRYPT_P,
            salt,
        }
    }
}
