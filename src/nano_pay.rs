use crate::program::to_script_hash;
use crate::rpc::{get_height, send_raw_transaction, RPCConfig, RPCClient, SignerRPCClient};
use crate::transaction::{unpack_payload_data, Payload, Transaction};
use crate::vault::{AccountHolder, Wallet};

use rand::{thread_rng, Rng};
use std::{
    sync::{Arc, Mutex},
    time::{UNIX_EPOCH, Duration, SystemTime},
};
use tokio::{task, time::sleep};

const SENDER_EXPIRATION_DELTA: u64 = 5;
const FORCE_FLUSH_DELTA: u64 = 2;
const RECEIVER_EXPIRATION_DELTA: u64 = 3;
const CONSENSUS_DURATION: u64 = 20;

fn clone_rpc_config(rpc_config: &RPCConfig) -> RPCConfig {
    RPCConfig {
        rpc_server_address: rpc_config.rpc_server_address.clone(),
        ..*rpc_config
    }
}

pub struct NanoPay<'a> {
    rpc_config: RPCConfig,
    wallet: &'a Wallet,
    recipient_address: String,
    recipient_program_hash: Vec<u8>,
    fee: i64,
    duration: u64,
    id: u64,
    amount: i64,
    expiration: u64,
}

impl<'a> NanoPay<'a> {
    pub fn new(
        rpc_config: RPCConfig,
        wallet: &'a Wallet,
        recipient_address: &str,
        fee: i64,
        duration: u64,
    ) -> Result<Self, String> {
        let recipient_program_hash = to_script_hash(recipient_address)?;

        let mut rng = thread_rng();
        let id = rng.gen();

        Ok(Self {
            rpc_config,
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
        let height = get_height(clone_rpc_config(&self.rpc_config)).await?;

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

pub struct NanoPayClaimer {
    rpc_config: Arc<RPCConfig>,
    recipient_address: String,
    recipient_program_hash: Vec<u8>,
    id: Option<u64>,
    min_flush_amount: Arc<i64>,
    amount: Arc<Mutex<i64>>,
    closed: Arc<Mutex<bool>>,
    expiration: Arc<Mutex<u64>>,
    last_claim_time: Arc<Mutex<SystemTime>>,
    prev_claimed_amount: Arc<Mutex<i64>>,
    prev_flush_amount: Arc<Mutex<i64>>,
    tx: Arc<Mutex<Option<Transaction>>>,
}

impl NanoPayClaimer {
    pub fn new(
        rpc_config: RPCConfig,
        recipient_address: &str,
        claim_interval_ms: u64,
        min_flush_amount: i64,
    ) -> Result<Self, String> {
        let recipient_program_hash = to_script_hash(recipient_address)?;

        let rpc_config = Arc::new(rpc_config);
        let min_flush_amount = Arc::new(min_flush_amount);
        let amount = Arc::new(Mutex::new(0));
        let closed = Arc::new(Mutex::new(false));
        let expiration = Arc::new(Mutex::new(0));
        let last_claim_time = Arc::new(Mutex::new(SystemTime::now()));
        let prev_claimed_amount = Arc::new(Mutex::new(0));
        let prev_flush_amount = Arc::new(Mutex::new(0));
        let tx = Arc::new(Mutex::new(None));

        let rpc_config_clone = rpc_config.clone();
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
                    break;
                }

                if tx_clone.lock().unwrap().is_none() {
                    continue;
                }

                if *amount_clone.lock().unwrap() - *prev_flush_amount_clone.lock().unwrap()
                    < *min_flush_amount_clone
                {
                    continue;
                }

                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let last_claim_duration = last_claim_time_clone.lock().unwrap().duration_since(UNIX_EPOCH).unwrap();
                let claim_interval_duration = Duration::from_millis(claim_interval_ms);

                if now < last_claim_duration + claim_interval_duration {
                    let res = get_height(clone_rpc_config(&*rpc_config_clone)).await;
                    let height = match res {
                        Ok(height) => height,
                        Err(_) => break,
                    };
                    let expiration = *expiration_clone.lock().unwrap();

                    if expiration > height + FORCE_FLUSH_DELTA {
                        let duration1 = last_claim_duration + claim_interval_duration - now;
                        let duration2 = Duration::from_secs((expiration - height + FORCE_FLUSH_DELTA) * CONSENSUS_DURATION);

                        sleep(if duration1 > duration2 {
                            duration2
                        } else {
                            duration1
                        }).await;

                        if *closed_clone.lock().unwrap() {
                            break;
                        }
                    }
                }

                let res = flush(
                    false,
                    rpc_config_clone.clone(),
                    amount_clone.clone(),
                    prev_flush_amount_clone.clone(),
                    min_flush_amount_clone.clone(),
                    expiration_clone.clone(),
                    last_claim_time_clone.clone(),
                    tx_clone.clone(),
                )
                .await;

                if res.is_err() {
                    break;
                }
            }

            flush(
                false,
                rpc_config_clone.clone(),
                amount_clone.clone(),
                prev_flush_amount_clone.clone(),
                min_flush_amount_clone.clone(),
                expiration_clone.clone(),
                last_claim_time_clone.clone(),
                tx_clone.clone(),
            )
            .await.unwrap();
        });

        Ok(Self {
            recipient_address: recipient_address.into(),
            recipient_program_hash,
            id: None,
            rpc_config,
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
        flush(
            force,
            self.rpc_config.clone(),
            self.amount.clone(),
            self.prev_flush_amount.clone(),
            self.min_flush_amount.clone(),
            self.expiration.clone(),
            self.last_claim_time.clone(),
            self.tx.clone(),
        )
        .await
    }

    pub fn claim(&self, tx: Transaction) -> i64 {
        todo!()
    }
}

async fn flush(
    force: bool,
    rpc_config: Arc<RPCConfig>,
    amount: Arc<Mutex<i64>>,
    prev_flush_amount: Arc<Mutex<i64>>,
    min_flush_amount: Arc<i64>,
    expiration: Arc<Mutex<u64>>,
    last_claim_time: Arc<Mutex<SystemTime>>,
    tx: Arc<Mutex<Option<Transaction>>>,
) -> Result<(), String> {
    if !force && *amount.lock().unwrap() - *prev_flush_amount.lock().unwrap() < *min_flush_amount {
        return Ok(());
    }

    if tx.lock().unwrap().is_none() {
        return Ok(());
    }

    let payload = unpack_payload_data(
        &tx.lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .unsigned_tx
            .payload_data,
    );

    match payload {
        Payload::NanoPay { amount, .. } => {
            {
                let tx = tx.lock().unwrap().as_ref().unwrap().clone();
                send_raw_transaction(&tx, clone_rpc_config(&*rpc_config)).await?;
            }

            *tx.lock().unwrap() = None;
            *expiration.lock().unwrap() = 0;
            *last_claim_time.lock().unwrap() = SystemTime::now();
            *prev_flush_amount.lock().unwrap() = amount;

            Ok(())
        }
        _ => Err("not a NanoPay payload".into()),
    }
}
