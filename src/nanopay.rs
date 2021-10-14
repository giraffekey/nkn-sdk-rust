use crate::program::to_script_hash;
use crate::rpc::{RPCClient, SignerRPCClient};
use crate::transaction::Transaction;
use crate::vault::{AccountHolder, Wallet};

use rand::{thread_rng, Rng};
use std::time::SystemTime;

const SENDER_EXPIRATION_DELTA: u32 = 5;
const FORCE_FLUSH_DELTA: u32 = 2;
const RECEIVER_EXPIRATION_DELTA: u32 = 3;

pub struct NanoPay<'a> {
    rpc_client: &'a dyn RPCClient,
    wallet: &'a Wallet,
    recipient_address: String,
    recipient_program_hash: Vec<u8>,
    fee: u64,
    duration: u32,
    id: u64,
    amount: u64,
    expiration: u32,
}

impl<'a> NanoPay<'a> {
    pub fn new(
        rpc_client: &'a dyn RPCClient,
        wallet: &'a Wallet,
        recipient_address: &str,
        fee: u64,
        duration: u32,
    ) -> Self {
        let recipient_program_hash = to_script_hash(recipient_address);

        let mut rng = thread_rng();
        let id = rng.gen();

        Self {
            rpc_client,
            wallet,
            recipient_address: recipient_address.into(),
            recipient_program_hash,
            fee,
            duration,
            amount: 0,
            expiration: 0,
            id,
        }
    }

    pub fn recipient(&self) -> &str {
        &self.recipient_address
    }

    pub async fn increment_amount(&mut self, delta: u64) -> Result<Transaction, String> {
        let height = self.rpc_client.height().await?;

        if self.expiration == 0 || self.expiration <= height + SENDER_EXPIRATION_DELTA {
            let mut rng = thread_rng();
            self.id = rng.gen();
            self.expiration = height + self.duration;
            self.amount = 0;
        }

        self.amount += delta;

        let mut tx = Transaction::new_nano_pay(self.wallet.program_hash(), &self.recipient_program_hash, self.id, self.amount, self.expiration, self.expiration);
        tx.unsigned_tx.fee = self.fee;
        self.wallet.sign_transaction(&mut tx);

        Ok(tx)
    }
}

pub struct NanoPayClaimer<'a> {
    rpc_client: &'a dyn RPCClient,
    recipient_address: String,
    recipient_program_hash: Vec<u8>,
    min_flush_amount: u64,
    amount: u64,
    closed: bool,
    expiration: u32,
    last_claim_time: SystemTime,
    prev_claimed_amount: u64,
    prev_flush_amount: u64,
    id: Option<u64>,
    tx: Option<Transaction>,
}

impl<'a> NanoPayClaimer<'a> {
    pub fn new(
        rpc_client: &'a dyn RPCClient,
        recipient_address: &str,
        claim_intervals_ms: u32,
        min_flush_amount: u64,
    ) -> Self {
        let recipient_program_hash = to_script_hash(recipient_address);

        let this = Self {
            rpc_client,
            recipient_address: recipient_address.into(),
            recipient_program_hash,
            min_flush_amount,
            amount: 0,
            closed: false,
            expiration: 0,
            last_claim_time: SystemTime::now(),
            prev_claimed_amount: 0,
            prev_flush_amount: 0,
            id: None,
            tx: None,
        };

        todo!()

        // this
    }

    pub fn recipient(&self) -> &str {
        &self.recipient_address
    }

    pub fn amount(&self) -> u64 {
        todo!()
    }

    pub fn close(&self) {
        todo!()
    }

    pub fn is_closed(&self) -> bool {
        todo!()
    }

    pub fn flush(&self) {
        todo!()
    }

    pub fn claim(&self, tx: Transaction) -> u64 {
        todo!()
    }
}
