use crate::constant::{DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT, DEFAULT_SEED_RPC_SERVER, MIN_NAME_REGISTRATION_FEE};
use crate::program::{create_program_hash, to_script_hash};
use crate::crypto::{
    aes_decrypt, aes_encrypt, ed25519_exchange, ed25519_private_key_to_curve25519_private_key,
    ed25519_public_key_to_curve25519_public_key, ed25519_sign, sha256_hash, IV_LEN, PUBLIC_KEY_LEN,
    SEED_LEN, SHA256_LEN, SHARED_KEY_LEN, SIGNATURE_LEN,
};
use crate::message::{Message, MessageConfig, MessagePayload, PayloadMessage};
use crate::nano_pay::{NanoPay, NanoPayClaimer};
use crate::rpc::{
    get_balance, get_height, get_nonce, get_registrant, get_subscribers,
    get_subscribers_count, get_subscription, send_raw_transaction, Node, Registrant,
    Subscribers, Subscription,
};
use crate::sigchain::{SigAlgo, SigChain, SigChainElement};
use crate::transaction::{Transaction, TransactionConfig};
use crate::util::{client_config_to_rpc_config, wallet_config_to_rpc_config};
use crate::vault::{Account, AccountHolder, Wallet, WalletConfig};

use flate2::{write::ZlibEncoder, Compression};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::Write,
    str,
    sync::{Arc, Mutex, mpsc::{channel, Sender, Receiver}},
    time::Duration,
};
use tokio::{task, time::sleep};

const MAX_CLIENT_MESSAGE_SIZE: usize = 4000000;

#[derive(Debug, Deserialize, Serialize)]
enum ClientMessageType {
    OutboundMessage = 0,
    InboundMessage = 1,
    Receipt = 2,
}

#[derive(Debug, Deserialize, Serialize)]
enum CompressionType {
    CompressionNone = 0,
    CompressionZlib = 1,
}

#[derive(Debug, Deserialize, Serialize)]
struct ClientMessage {
    message_type: ClientMessageType,
    message: Vec<u8>,
    compression_type: CompressionType,
}

#[derive(Debug, Deserialize, Serialize)]
struct OutboundMessage {
    dest: String,
    dests: Vec<String>,
    payload: Vec<u8>,
    max_holding_seconds: u32,
    nonce: u32,
    block_hash: Vec<u8>,
    signatures: Vec<Vec<u8>>,
    payloads: Vec<Vec<u8>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct InboundMessage {
    src: String,
    payload: Vec<u8>,
    prev_hash: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Receipt {
    prev_hash: Vec<u8>,
    signature: Vec<u8>,
}

fn parse_client_address(address_str: &str) -> Result<([u8; SHA256_LEN], Vec<u8>, String), String> {
    let client_id = sha256_hash(address_str.as_bytes());
    let substrings: Vec<&str> = address_str.split(".").collect();
    let public_key_str = substrings.last().unwrap();
    let public_key = hex::decode(public_key_str)
        .map_err(|_| "Invalid public key string converting to hex".to_string())?;
    let identifier = substrings[..substrings.len() - 1].join(".");
    Ok((client_id, public_key, identifier))
}

#[derive(Debug)]
pub struct ClientConfig {
    pub rpc_server_address: Vec<String>,
    pub rpc_timeout: Duration,
    pub rpc_concurrency: u32,
    pub msg_chan_length: usize,
    pub connect_retries: u32,
    pub msg_cache_expiration: u64,
    pub msg_cache_cleanup_interval: u64,
    pub ws_handshake_timeout: u64,
    pub ws_write_timeout: u64,
    pub min_reconnect_interval: u64,
    pub max_reconnect_interval: u64,
    pub default_message_config: Option<MessageConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            rpc_server_address: DEFAULT_SEED_RPC_SERVER
                .iter()
                .map(|s| s.to_string())
                .collect(),
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            rpc_concurrency: DEFAULT_RPC_CONCURRENCY,
            msg_chan_length: 1024,
            connect_retries: 3,
            msg_cache_expiration: 300000,
            msg_cache_cleanup_interval: 60000,
            ws_handshake_timeout: 5000,
            ws_write_timeout: 10000,
            min_reconnect_interval: 1000,
            max_reconnect_interval: 64000,
            default_message_config: None,
        }
    }
}

pub struct Client {
    config: ClientConfig,
    account: Account,
    wallet: Wallet,
    address: String,
    address_id: [u8; SHA256_LEN],
    curve_secret_key: [u8; SHARED_KEY_LEN],
    closed: Arc<Mutex<bool>>,
    node: Option<Node>,
    sig_chain_block_hash: Option<String>,
    connect_channel: (Sender<Node>, Receiver<Node>),
    message_channel: (Sender<Message>, Receiver<Message>),
    response_channels: HashMap<String, (Sender<Message>, Receiver<Message>)>,
    shared_keys: Arc<Mutex<HashMap<String, [u8; SHARED_KEY_LEN]>>>,
}

impl Client {
    pub fn new(
        account: Account,
        identifier: Option<String>,
        config: ClientConfig,
    ) -> Result<Self, String> {
        let wallet_config = WalletConfig {
            rpc_server_address: config.rpc_server_address.clone(),
            ..WalletConfig::default()
        };
        let wallet = Wallet::new(account.clone(), wallet_config)?;
        let curve_secret_key = ed25519_private_key_to_curve25519_private_key(account.private_key());

        let closed = Arc::new(Mutex::new(false));

        let pub_key_hex = hex::encode(account.public_key());
        let address = if let Some(identifier) = identifier {
            if identifier.is_empty() {
                pub_key_hex
            } else {
                format!("{:?}.{:?}", identifier, pub_key_hex)
            }
        } else {
            pub_key_hex
        };
        let address_id = sha256_hash(address.as_bytes());

        let shared_keys = Arc::new(Mutex::new(HashMap::new()));

        Ok(Self {
            config,
            account,
            wallet,
            address,
            address_id,
            curve_secret_key,
            closed,
            node: None,
            sig_chain_block_hash: None,
            connect_channel: channel(),
            message_channel: channel(),
            response_channels: HashMap::new(),
            shared_keys,
        })
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: ClientConfig) {
        self.config = config;
    }

    pub fn private_key(&self) -> &[u8] {
        self.account.private_key()
    }

    pub fn public_key(&self) -> &[u8] {
        self.account.public_key()
    }

    pub fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap()
    }

    pub fn close(&mut self) {
        *self.closed.lock().unwrap() = true;
        todo!()
    }

    pub fn connection(&self) {
        todo!() // return WS connection
    }

    pub fn wait_for_connect(&self) -> Result<Node, String> {
        let (_, rx) = &self.connect_channel;
        rx.recv().map_err(|_| "Receiver failed".into())
    }

    pub fn wait_for_message(&self) -> Result<Message, String> {
        let (_, rx) = &self.message_channel;
        rx.recv().map_err(|_| "Receiver failed".into())
    }

    async fn connect(&self, max_retries: u32) -> Result<(), String> {
        todo!()
    }

    pub async fn reconnect(&mut self) -> Result<(), String> {
        if *self.closed.lock().unwrap() {
            return Ok(());
        }

        log::info!("Reconnect in {} ms...", self.config.min_reconnect_interval);
        sleep(Duration::from_millis(self.config.min_reconnect_interval)).await;

        if let Err(err) = self.connect(0).await {
            self.close();
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn node(&self) -> &Option<Node> {
        &self.node
    }

    fn get_or_compute_shared_key(
        &self,
        remote_public_key: &[u8],
    ) -> Result<[u8; SHARED_KEY_LEN], String> {
        let remote_public_key_str = str::from_utf8(remote_public_key).unwrap();
        let shared_keys = self.shared_keys.lock().unwrap();

        if let Some(shared_key) = shared_keys.get(remote_public_key_str) {
            Ok(*shared_key)
        } else {
            drop(shared_keys);

            if remote_public_key.len() != PUBLIC_KEY_LEN {
                return Err("invalid public key size".into());
            }

            let curve_public_key = ed25519_public_key_to_curve25519_public_key(&remote_public_key);
            let shared_key = ed25519_exchange(&curve_public_key, &self.curve_secret_key);

            self.shared_keys
                .lock()
                .unwrap()
                .insert(remote_public_key_str.into(), shared_key);

            Ok(shared_key)
        }
    }

    fn encrypt_payload(
        &self,
        payload: MessagePayload,
        dests: &[String],
    ) -> Result<Vec<Vec<u8>>, String> {
        let raw_payload = serde_json::to_vec(&payload).unwrap();
        let mut rng = thread_rng();

        if dests.len() > 1 {
            let mut key = [0u8; SHARED_KEY_LEN];
            rng.fill(&mut key);

            let mut msg_nonce = [0u8; IV_LEN];
            rng.fill(&mut msg_nonce);

            let encrypted_payload = aes_encrypt(&raw_payload, &key, &msg_nonce);

            let mut msgs = Vec::new();

            for dest in dests {
                let (_, dest_pubkey, _) = parse_client_address(dest)?;
                let shared_key = self.get_or_compute_shared_key(&dest_pubkey)?;

                let mut key_nonce = [0u8; IV_LEN];
                rng.fill(&mut key_nonce);

                let encrypted_key = aes_encrypt(&key, &shared_key, &key_nonce);
                let nonce = [key_nonce, msg_nonce].concat();

                msgs.push(
                    serde_json::to_vec(&PayloadMessage {
                        payload: encrypted_payload.clone(),
                        encrypted: true,
                        nonce,
                        encrypted_key,
                    })
                    .unwrap(),
                );
            }

            Ok(msgs)
        } else {
            let (_, dest_pubkey, _) = parse_client_address(&dests[0])?;
            let shared_key = self.get_or_compute_shared_key(&dest_pubkey)?;

            let mut nonce = [0u8; IV_LEN];
            rng.fill(&mut nonce);

            let encrypted_payload = aes_encrypt(&raw_payload, &shared_key, &nonce);

            Ok(vec![serde_json::to_vec(&PayloadMessage {
                payload: encrypted_payload,
                encrypted: true,
                nonce: nonce.to_vec(),
                encrypted_key: Vec::new(),
            })
            .unwrap()])
        }
    }

    fn decrypt_payload(&self, msg: PayloadMessage, src_address: &str) -> Result<Vec<u8>, String> {
        let encrypted_payload = msg.payload;
        let (_, src_pubkey, _) = parse_client_address(src_address)?;

        if !msg.encrypted_key.is_empty() {
            let shared_key = self.get_or_compute_shared_key(&src_pubkey)?;
            let key = aes_decrypt(&msg.encrypted_key, &shared_key, &msg.nonce[..IV_LEN]);
            let payload = aes_decrypt(&encrypted_payload, &key, &msg.nonce[IV_LEN..]);
            Ok(payload)
        } else {
            let shared_key = self.get_or_compute_shared_key(&src_pubkey)?;
            let payload = aes_decrypt(&encrypted_payload, &shared_key, &msg.nonce);
            Ok(payload)
        }
    }

    async fn write_message(&self, data: &[u8]) -> Result<(), String> {
        todo!();
        self.reconnect().await
    }

    async fn process_dests(&self, dests: &[&str]) -> Result<Vec<String>, String> {
        if dests.is_empty() {
            return Ok(Vec::new());
        }

        let mut processed_dests = Vec::new();

        for dest in dests {
            let mut address: Vec<String> = dest.split('.').map(|s| s.to_string()).collect();

            if address.last().unwrap().len() < 2 * PUBLIC_KEY_LEN {
                let reg = match self.registrant(address.last().unwrap()).await {
                    Ok(reg) => reg,
                    Err(_) => continue,
                };

                if reg.registrant.is_empty() {
                    continue;
                }

                *address.last_mut().unwrap() = reg.registrant;
            }

            let processed_dest = address.join(".");

            processed_dests.push(processed_dest);
        }

        if processed_dests.is_empty() {
            Err("invalid destination".into())
        } else {
            Ok(processed_dests)
        }
    }

    fn create_payloads(
        &self,
        dests: &[String],
        payload: MessagePayload,
        encrypted: bool,
    ) -> Result<Vec<Vec<u8>>, String> {
        if encrypted {
            Ok(self.encrypt_payload(payload, dests)?)
        } else {
            let payload = serde_json::to_vec(&payload).unwrap();
            let payload = serde_json::to_vec(&PayloadMessage {
                payload,
                encrypted: false,
                nonce: Vec::new(),
                encrypted_key: Vec::new(),
            })
            .unwrap();
            Ok(vec![payload])
        }
    }

    fn create_outbound_message(
        &self,
        dests: &[&str],
        payloads: &[&[u8]],
        encrypted: bool,
        max_holding_seconds: u32,
    ) -> Result<OutboundMessage, String> {
        let mut outbound_msg = OutboundMessage {
            dest: String::new(),
            dests: dests.iter().map(|s| s.to_string()).collect(),
            payload: Vec::new(),
            max_holding_seconds,
            nonce: 0,
            block_hash: Vec::new(),
            signatures: Vec::new(),
            payloads: payloads.iter().map(|v| v.to_vec()).collect(),
        };

        let node_public_key = hex::decode(&self.node.as_ref().unwrap().public_key).unwrap();
        let sig_chain_element = SigChainElement {
            id: Vec::new(),
            next_pubkey: node_public_key,
            mining: false,
            signature: Vec::new(),
            sig_algo: SigAlgo::Signature,
            vrf: Vec::new(),
            proof: Vec::new(),
        };
        let sig_chain_element_ser = sig_chain_element.serialize_unsigned();

        let mut rng = thread_rng();
        let nonce = rng.gen();

        let mut sig_chain = SigChain {
            nonce,
            data_size: 0,
            block_hash: Vec::new(),
            src_id: self.address_id.to_vec(),
            src_pubkey: self.public_key().to_vec(),
            dest_id: Vec::new(),
            dest_pubkey: Vec::new(),
            elems: vec![sig_chain_element],
        };

        if let Some(sig_chain_block_hash) = &self.sig_chain_block_hash {
            let sig_chain_block_hash = hex::decode(sig_chain_block_hash).unwrap();
            sig_chain.block_hash = sig_chain_block_hash.clone();
            outbound_msg.block_hash = sig_chain_block_hash.clone();
        }

        let mut signatures = Vec::new();

        for (i, dest) in dests.iter().enumerate() {
            let (dest_id, dest_public_key, _) = parse_client_address(dest)?;
            sig_chain.dest_id = dest_id.to_vec();
            sig_chain.dest_pubkey = dest_public_key;

            if payloads.len() > 1 {
                sig_chain.data_size = payloads[i].len() as u32;
            } else {
                sig_chain.data_size = payloads[0].len() as u32;
            }

            let metadata = sig_chain.serialize_metadata();
            let mut digest = sha256_hash(&metadata).to_vec();
            digest.extend_from_slice(&sig_chain_element_ser);
            let digest = sha256_hash(&digest);

            let signature = ed25519_sign(self.private_key(), &digest);
            signatures.push(signature.to_vec());
        }

        outbound_msg.signatures = signatures;
        outbound_msg.nonce = nonce;
        Ok(outbound_msg)
    }

    fn create_client_message(
        &self,
        outbound_msg: &OutboundMessage,
    ) -> Result<ClientMessage, String> {
        let outbound_msg_data = serde_json::to_vec(outbound_msg).unwrap();

        if outbound_msg.payloads.len() > 1 {
            let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
            e.write_all(&outbound_msg_data);
            let message = e.finish().unwrap();

            Ok(ClientMessage {
                message_type: ClientMessageType::OutboundMessage,
                compression_type: CompressionType::CompressionZlib,
                message,
            })
        } else {
            Ok(ClientMessage {
                message_type: ClientMessageType::OutboundMessage,
                compression_type: CompressionType::CompressionNone,
                message: outbound_msg_data,
            })
        }
    }

    async fn send_messages(
        &self,
        dests: &[&str],
        payload: MessagePayload,
        encrypted: bool,
        max_holding_seconds: u32,
        ws_write_timeout: u64,
    ) -> Result<(), String> {
        let dests = self.process_dests(dests).await?;

        if dests.is_empty() {
            return Ok(());
        }

        let payloads = self.create_payloads(&dests, payload, encrypted)?;

        let mut outbound_msgs = Vec::new();
        let mut dest_list = Vec::new();
        let mut payload_list = Vec::new();

        if payloads.len() > 1 {
            let mut total_size = 0;

            for i in 0..payloads.len() {
                let size = payloads[i].len() + dests[i].len() + SIGNATURE_LEN;

                if size > MAX_CLIENT_MESSAGE_SIZE {
                    return Err("message oversize".into());
                }

                if total_size + size > MAX_CLIENT_MESSAGE_SIZE {
                    outbound_msgs.push(self.create_outbound_message(
                        &dest_list,
                        &payload_list,
                        encrypted,
                        max_holding_seconds,
                    )?);
                    dest_list.clear();
                    payload_list.clear();
                    total_size = 0;
                }

                dest_list.push(&dests[i]);
                payload_list.push(&payloads[i]);
                total_size += size;
            }
        } else {
            let mut size = payloads[0].len();

            for dest in &dests {
                size += dest.len() + SIGNATURE_LEN;
            }

            if size > MAX_CLIENT_MESSAGE_SIZE {
                return Err("message oversize".into());
            }

            dest_list = dests.iter().map(|s| s.as_str()).collect();
            payload_list = payloads.iter().map(|p| p.as_slice()).collect();
        }

        outbound_msgs.push(self.create_outbound_message(
            &dest_list,
            &payload_list,
            encrypted,
            max_holding_seconds,
        )?);

        if outbound_msgs.len() > 1 {
            log::info!(
                "Client message size is greater than {} bytes, split into {} batches.",
                MAX_CLIENT_MESSAGE_SIZE,
                outbound_msgs.len()
            );
        }

        for outbound_msg in outbound_msgs {
            let client_msg = self.create_client_message(&outbound_msg)?;
            self.write_message(&serde_json::to_vec(&client_msg).unwrap());
        }

        Ok(())
    }

    async fn publish(
        &self,
        topic: &str,
        payload: MessagePayload,
        config: MessageConfig,
    ) -> Result<(), String> {
        let subscribers = self
            .subscribers(topic, config.offset, config.limit, false, config.tx_pool)
            .await?;

        let mut dests = Vec::new();
        let mut offset = config.offset;

        for subscriber in subscribers.subscribers.keys() {
            dests.push(subscriber.clone());
        }

        while offset <= subscribers.subscribers.len() as u32 {
            offset += config.limit;

            let subscribers = self
                .subscribers(topic, config.offset, config.limit, false, false)
                .await?;

            for subscriber in subscribers.subscribers.keys() {
                dests.push(subscriber.clone());
            }
        }

        if config.tx_pool {
            for subscriber in subscribers.subscribers_in_tx_pool.keys() {
                dests.push(subscriber.clone());
            }
        }

        let dests: Vec<&str> = dests.iter().map(|s| s.as_str()).collect();
        self.send_messages(
            &dests,
            payload,
            !config.unencrypted,
            config.max_holding_seconds,
            self.config.ws_write_timeout,
        )
        .await?;

        Ok(())
    }

    pub async fn publish_binary(
        &self,
        topic: &str,
        data: &[u8],
        config: MessageConfig,
    ) -> Result<(), String> {
        let payload = MessagePayload::new_binary(data, &config.message_id, &[], true);
        self.publish(topic, payload, config).await
    }

    pub async fn publish_text(
        &self,
        topic: &str,
        text: &str,
        config: MessageConfig,
    ) -> Result<(), String> {
        let payload = MessagePayload::new_text(text, &config.message_id, &[], true);
        self.publish(topic, payload, config).await
    }

    pub async fn send(&mut self, dests: &[&str], payload: MessagePayload, config: MessageConfig) -> Result<(), String> {
        let message_id = payload.message_id.clone();

        self.send_messages(dests, payload, !config.unencrypted, config.max_holding_seconds, self.config.ws_write_timeout).await?;

        if !config.no_reply {
            let message_id = str::from_utf8(&message_id).unwrap();
            self.response_channels.insert(message_id.into(), channel());
        }

        Ok(())
    }

    pub async fn send_binary(&mut self, dests: &[&str], data: &[u8], config: MessageConfig) -> Result<(), String> {
        let payload = MessagePayload::new_binary(data, &config.message_id, &[], true);
        self.send(dests, payload, config).await
    }

    pub async fn send_text(&mut self, dests: &[&str], text: &str, config: MessageConfig) -> Result<(), String> {
        let payload = MessagePayload::new_text(text, &config.message_id, &[], true);
        self.send(dests, payload, config).await
    }

    pub fn set_write_deadline(&self, deadline: u64) {
        todo!()
    }

    pub fn create_nano_pay(
        &self,
        recipient_address: &str,
        fee: i64,
        duration: u64,
    ) -> Result<NanoPay, String> {
        NanoPay::new(
            client_config_to_rpc_config(&self.config),
            &self.wallet,
            recipient_address,
            fee,
            duration,
        )
    }

    pub fn create_nano_pay_claimer(
        &self,
        recipient_address: &str,
        claim_interval_ms: u64,
        min_flush_amount: i64,
    ) -> Result<NanoPayClaimer, String> {
        let recipient_address = if recipient_address.is_empty() {
            self.wallet.address()
        } else {
            recipient_address.into()
        };
        NanoPayClaimer::new(
            client_config_to_rpc_config(&self.config),
            &recipient_address,
            claim_interval_ms,
            min_flush_amount,
        )
    }

    pub fn sign_transaction(&self, tx: &mut Transaction) {
        self.wallet.sign_transaction(tx);
    }

    pub async fn nonce(&self, tx_pool: bool) -> Result<u64, String> {
        self.nonce_by_address(&self.wallet.address(), tx_pool).await
    }

    pub async fn nonce_by_address(&self, address: &str, tx_pool: bool) -> Result<u64, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_nonce(address, tx_pool, client_config_to_rpc_config(&self.config)).await
        } else {
            get_nonce(
                address,
                tx_pool,
                wallet_config_to_rpc_config(&wallet_config),
            )
            .await
        }
    }

    pub async fn balance(&self) -> Result<i64, String> {
        self.balance_by_address(&self.wallet.address()).await
    }

    pub async fn balance_by_address(&self, address: &str) -> Result<i64, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_balance(address, client_config_to_rpc_config(&self.config)).await
        } else {
            get_balance(address, wallet_config_to_rpc_config(&wallet_config)).await
        }
    }

    pub async fn height(&self) -> Result<u64, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_height(client_config_to_rpc_config(&self.config)).await
        } else {
            get_height(wallet_config_to_rpc_config(&wallet_config)).await
        }
    }

    pub async fn subscribers(
        &self,
        topic: &str,
        offset: u32,
        limit: u32,
        meta: bool,
        tx_pool: bool,
    ) -> Result<Subscribers, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_subscribers(
                topic,
                offset,
                limit,
                meta,
                tx_pool,
                client_config_to_rpc_config(&self.config),
            )
            .await
        } else {
            get_subscribers(
                topic,
                offset,
                limit,
                meta,
                tx_pool,
                wallet_config_to_rpc_config(&wallet_config),
            )
            .await
        }
    }

    pub async fn subscription(&self, topic: &str, subscriber: &str) -> Result<Subscription, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_subscription(topic, subscriber, client_config_to_rpc_config(&self.config)).await
        } else {
            get_subscription(
                topic,
                subscriber,
                wallet_config_to_rpc_config(&wallet_config),
            )
            .await
        }
    }

    pub async fn suscribers_count(
        &self,
        topic: &str,
        subscriber_hash_prefix: &[u8],
    ) -> Result<u32, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_subscribers_count(
                topic,
                subscriber_hash_prefix,
                client_config_to_rpc_config(&self.config),
            )
            .await
        } else {
            get_subscribers_count(
                topic,
                subscriber_hash_prefix,
                wallet_config_to_rpc_config(&wallet_config),
            )
            .await
        }
    }

    pub async fn registrant(&self, name: &str) -> Result<Registrant, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_registrant(name, client_config_to_rpc_config(&self.config)).await
        } else {
            get_registrant(name, wallet_config_to_rpc_config(&wallet_config)).await
        }
    }

    pub async fn send_raw_transaction(&self, txn: &Transaction) -> Result<String, String> {
        let wallet_config = self.wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            send_raw_transaction(txn, client_config_to_rpc_config(&self.config)).await
        } else {
            send_raw_transaction(txn, wallet_config_to_rpc_config(&wallet_config)).await
        }
    }

    pub async fn transfer(
        &self,
        address: &str,
        amount: i64,
        config: TransactionConfig,
    ) -> Result<String, String> {
        let sender = create_program_hash(self.public_key());
        let recipient = to_script_hash(address)?;

        let nonce = if config.nonce > 0 {
            config.nonce
        } else {
            self.nonce(true).await?
        };

        let mut tx = Transaction::new_transfer_asset(&sender, &recipient, nonce, amount, config.fee);

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }

    pub async fn register_name(&self, name: &str, config: TransactionConfig) -> Result<String, String> {
        let nonce = if config.nonce > 0 {
            config.nonce
        } else {
            self.nonce(true).await?
        };

        let mut tx = Transaction::new_register_name(
            self.public_key(),
            name,
            nonce,
            MIN_NAME_REGISTRATION_FEE,
            config.fee,
        );

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }

    pub async fn transfer_name(
        &self,
        name: &str,
        recipient_public_key: &[u8],
        config: TransactionConfig,
    ) -> Result<String, String> {
        let nonce = if config.nonce > 0 {
            config.nonce
        } else {
            self.nonce(true).await?
        };

        let mut tx = Transaction::new_transfer_name(
            self.public_key(),
            recipient_public_key,
            name,
            nonce,
            config.fee,
        );

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }

    pub async fn delete_name(&self, name: &str, config: TransactionConfig) -> Result<String, String> {
        let nonce = if config.nonce > 0 {
            config.nonce
        } else {
            self.nonce(true).await?
        };

        let mut tx = Transaction::new_delete_name(self.public_key(), name, nonce, config.fee);

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }

    pub async fn subscribe(
        &self,
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
        let nonce = if config.nonce > 0 {
            config.nonce
        } else {
            self.nonce(true).await?
        };

        let mut tx = Transaction::new_subscribe(
            self.public_key(),
            identifier,
            topic,
            duration,
            meta,
            nonce,
            config.fee,
        );

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }

    pub async fn unsubscribe(
        &self,
        identifier: &str,
        topic: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
        let nonce = if config.nonce > 0 {
            config.nonce
        } else {
            self.nonce(true).await?
        };

        let mut tx = Transaction::new_unsubscribe(self.public_key(), identifier, topic, nonce, config.fee);

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }
}

impl AccountHolder for Client {
    fn account(&self) -> &Account {
        &self.account
    }

    fn seed(&self) -> [u8; SEED_LEN] {
        self.account.seed()
    }

    fn address(&self) -> String {
        self.address.clone()
    }

    fn program_hash(&self) -> &[u8] {
        self.account.program_hash()
    }
}
