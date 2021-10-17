use crate::program::to_script_hash;
use crate::rpc::{RPCClient, SignerRPCClient};
use crate::transaction::{unpack_payload_data, Payload, Transaction};
use crate::vault::{AccountHolder, Wallet};

use rand::{thread_rng, Rng};
use std::{sync::{Arc, Mutex}, time::{Duration, SystemTime}};
use tokio::{task, time::sleep};

const SENDER_EXPIRATION_DELTA: u32 = 5;
const FORCE_FLUSH_DELTA: u32 = 2;
const RECEIVER_EXPIRATION_DELTA: u32 = 3;

pub struct NanoPay<'a> {
    rpc_client: &'a dyn RPCClient,
    wallet: &'a Wallet,
    recipient_address: String,
    recipient_program_hash: Vec<u8>,
    fee: i64,
    duration: u32,
    id: u64,
    amount: i64,
    expiration: u32,
}

impl<'a> NanoPay<'a> {
    pub fn new(
        rpc_client: &'a dyn RPCClient,
        wallet: &'a Wallet,
        recipient_address: &str,
        fee: i64,
        duration: u32,
    ) -> Result<Self, String> {
        let recipient_program_hash = to_script_hash(recipient_address)?;

        let mut rng = thread_rng();
        let id = rng.gen();

        Ok(Self {
            rpc_client,
            wallet,
            recipient_address: recipient_address.into(),
            recipient_program_hash,
            fee,
            duration,
            amount: 0,
            expiration: 0,
            id,
        })
    }

    pub fn recipient(&self) -> &str {
        &self.recipient_address
    }

    pub async fn increment_amount(&mut self, delta: i64) -> Result<Transaction, String> {
        let height = self.rpc_client.height().await?;

        if self.expiration == 0 || self.expiration <= height + SENDER_EXPIRATION_DELTA {
            let mut rng = thread_rng();
            self.id = rng.gen();
            self.expiration = height + self.duration;
            self.amount = 0;
        }

        self.amount += delta;

        let mut tx = Transaction::new_nano_pay(
            self.wallet.program_hash(),
            &self.recipient_program_hash,
            self.id,
            self.amount,
            self.expiration,
            self.expiration,
        );
        tx.unsigned_tx.fee = self.fee;
        self.wallet.sign_transaction(&mut tx);

        Ok(tx)
    }
}

pub struct NanoPayClaimer<'a> {
    recipient_address: String,
    recipient_program_hash: Vec<u8>,
    id: Option<u64>,
    rpc_client: Arc<&'a dyn RPCClient>,
    min_flush_amount: Arc<i64>,
    amount: Arc<Mutex<i64>>,
    closed: Arc<Mutex<bool>>,
    expiration: Arc<Mutex<u32>>,
    last_claim_time: Arc<Mutex<SystemTime>>,
    prev_claimed_amount: Arc<Mutex<i64>>,
    prev_flush_amount: Arc<Mutex<i64>>,
    tx: Arc<Mutex<Option<Transaction>>>,
}

impl<'a> NanoPayClaimer<'a> {
    pub fn new(
        rpc_client: &'a dyn RPCClient,
        recipient_address: &str,
        claim_intervals_ms: u32,
        min_flush_amount: i64,
    ) -> Result<Self, String> {
        let recipient_program_hash = to_script_hash(recipient_address)?;

        let rpc_client = Arc::new(rpc_client);
        let min_flush_amount = Arc::new(min_flush_amount);
        let amount = Arc::new(Mutex::new(0));
        let closed = Arc::new(Mutex::new(false));
        let expiration = Arc::new(Mutex::new(0));
        let last_claim_time = Arc::new(Mutex::new(SystemTime::now()));
        let prev_claimed_amount = Arc::new(Mutex::new(0));
        let prev_flush_amount = Arc::new(Mutex::new(0));
        let tx = Arc::new(Mutex::new(None));

        let rpc_client_clone = rpc_client.clone();
        let min_flush_amount_clone = min_flush_amount.clone();
        let amount_clone = amount.clone();
        let closed_clone = closed.clone();
        let expiration_clone = expiration.clone();
        let last_claim_time_clone = last_claim_time.clone();
        let prev_claimed_amount_clone = prev_claimed_amount.clone();
        let prev_flush_amount_clone = prev_flush_amount.clone();
        let tx_clone = tx.clone();

        task::spawn(async move {
            loop {
                sleep(Duration::from_secs(60)).await;

                if *closed_clone.lock().unwrap() {
                    return;
                }

                if tx_clone.lock().unwrap().is_none() {
                    continue;
                }

                if *amount_clone.lock().unwrap() - *prev_flush_amount_clone.lock().unwrap() < *min_flush_amount_clone {
                    continue;
                }

                todo!();
            }
        });

        Ok(Self {
            recipient_address: recipient_address.into(),
            recipient_program_hash,
            id: None,
            rpc_client,
            min_flush_amount,
            amount,
            closed,
            expiration,
            last_claim_time,
            prev_claimed_amount,
            prev_flush_amount,
            tx,
        })
    }

    pub fn recipient(&self) -> &str {
        &self.recipient_address
    }

    pub fn amount(&self) -> i64 {
        *self.prev_claimed_amount.lock().unwrap() + *self.amount.lock().unwrap()
    }

    pub fn close(&self) {
        *self.closed.lock().unwrap() = true;
    }

    pub fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap()
    }

    pub async fn flush(&self, force: bool) -> Result<(), String> {
        if !force && *self.amount.lock().unwrap() - *self.prev_flush_amount.lock().unwrap() < *self.min_flush_amount {
            return Ok(());
        }

        if self.tx.lock().unwrap().is_none() {
            return Ok(());
        }

        let payload = unpack_payload_data(&self.tx.lock().unwrap().as_ref().unwrap().unsigned_tx.payload_data);

        match payload {
            Payload::NanoPay { amount, .. } => {
                self.rpc_client.send_raw_transaction(self.tx.lock().unwrap().as_ref().unwrap()).await?;
                *self.tx.lock().unwrap() = None;
                *self.expiration.lock().unwrap() = 0;
                *self.last_claim_time.lock().unwrap() = SystemTime::now();
                *self.prev_flush_amount.lock().unwrap() = amount;
                Ok(())
            }
            _ => Err("not a NanoPay payload".into()),
        }
    }

    pub fn claim(&self, tx: Transaction) -> i64 {
        todo!()
    }
}
