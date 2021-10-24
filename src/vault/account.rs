use crate::constant::{MAXIMUM_PRECISION, STORAGE_FACTOR};
use crate::crypto::{
    ed25519_keypair, ed25519_seed_from_private_key, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, RIPEMD160_LEN,
    SEED_LEN,
};
use crate::program::{code_hash_to_address, create_program_hash};

use rand::Rng;

#[derive(Debug, Clone)]
pub struct Account {
    private_key: [u8; PRIVATE_KEY_LEN],
    public_key: [u8; PUBLIC_KEY_LEN],
    program_hash: [u8; RIPEMD160_LEN],
}

impl Account {
    pub fn new(seed: &[u8]) -> Result<Self, String> {
        if seed.len() != 32 {
            return Err("Invalid seed length".into());
        }

        let (private_key, public_key) = ed25519_keypair(seed);
        let program_hash = create_program_hash(&public_key);

        Ok(Self {
            private_key,
            public_key,
            program_hash,
        })
    }

    pub fn random() -> Result<Self, String> {
        let mut rng = rand::thread_rng();
        let mut seed = [0; 32];
        rng.fill(&mut seed);
        Self::new(&seed)
    }

    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn seed(&self) -> [u8; SEED_LEN] {
        ed25519_seed_from_private_key(&self.private_key)
    }

    pub fn program_hash(&self) -> &[u8] {
        &self.program_hash
    }

    pub fn wallet_address(&self) -> String {
        code_hash_to_address(&self.program_hash)
    }
}

pub fn string_to_amount(s: &str) -> Result<i64, String> {
    let mut result = String::new();

    if let Some(di) = s.find('.') {
        let precision = s.len() - di - 1;

        if precision > MAXIMUM_PRECISION {
            return Err("unsupported precision".into());
        }

        result.push_str(&s[..di]);
        result.push_str(&s[di + 1..]);

        for _ in 0..(MAXIMUM_PRECISION - precision) {
            result.push('0');
        }
    } else {
        result.push_str(s);
        for _ in 0..MAXIMUM_PRECISION {
            result.push('0');
        }
    }

    result.parse().map_err(|_| "parse error".into())
}

pub fn amount_to_string(amount: i64) -> String {
    let mut result = String::new();

    let value = if amount > 0 {
        amount
    } else {
        result.push('-');
        -amount
    };

    result.push_str((value / STORAGE_FACTOR).to_string().as_str());

    let value = value % STORAGE_FACTOR;

    if value > 0 {
        result.push('.');

        let s = value.to_string();

        for _ in s.len()..8 {
            result.push('0');
        }

        result.push_str(s.as_str());
    }

    result
}

pub trait AccountHolder {
    fn account(&self) -> &Account;
    fn seed(&self) -> [u8; SEED_LEN];
    fn address(&self) -> String;
    fn program_hash(&self) -> &[u8];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_to_amount_works() {
        assert_eq!(string_to_amount("100"), Ok(100_0000_0000));
        assert_eq!(string_to_amount("101.56"), Ok(101_5600_0000));
        assert_eq!(string_to_amount("10123.45678"), Ok(10123_4567_8000));
        assert_eq!(string_to_amount("123456"), Ok(123456_0000_0000));
        assert_eq!(
            string_to_amount("1.2345678901"),
            Err("unsupported precision".into())
        );
        assert_eq!(string_to_amount("1234e5"), Err("parse error".into()));
    }

    #[test]
    fn amount_to_string_works() {
        assert_eq!(amount_to_string(100_0000_0000), "100".to_string());
        assert_eq!(amount_to_string(101_5600_0000), "101.56000000".to_string());
        assert_eq!(
            amount_to_string(10123_4567_8000),
            "10123.45678000".to_string()
        );
        assert_eq!(amount_to_string(123456_0000_0000), "123456".to_string());
        assert_eq!(amount_to_string(123_4567_8901), "123.45678901".to_string());
        assert_eq!(
            amount_to_string(-123_4500_0000),
            "-123.45000000".to_string()
        );
    }
}
