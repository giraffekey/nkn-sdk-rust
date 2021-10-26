use crate::constant::{
    DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT, DEFAULT_SEED_RPC_SERVER,
    MIN_NAME_REGISTRATION_FEE,
};
use crate::crypto::{
    aes_decrypt, aes_encrypt, ed25519_exchange, ed25519_private_key_to_curve25519_private_key,
    ed25519_public_key_to_curve25519_public_key, ed25519_sign, sha256_hash, IV_LEN, PUBLIC_KEY_LEN,
    SEED_LEN, SHA256_LEN, SHARED_KEY_LEN, SIGNATURE_LEN,
};
use crate::error::NKNError;
use crate::message::{
    Message, MessageConfig, MessagePayload, MessagePayloadType, PayloadMessage, Reply, TextData,
};
use crate::nano_pay::{NanoPay, NanoPayClaimer};
use crate::program::{create_program_hash, to_script_hash};
use crate::rpc::{
    get_balance, get_height, get_node_state, get_nonce, get_registrant, get_subscribers,
    get_subscribers_count, get_subscription, get_ws_address, send_raw_transaction, Node, RPCConfig,
    Registrant, Subscribers, Subscription, SyncState,
};
use crate::sigchain::{SigAlgo, SigChain, SigChainElement};
use crate::transaction::{Transaction, TransactionConfig};
use crate::util::{client_config_to_rpc_config, wallet_config_to_rpc_config};
use crate::vault::{Account, AccountHolder, Wallet, WalletConfig};

use flate2::{write::ZlibEncoder, Compression};
use futures_util::{future, pin_mut, StreamExt};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use std::collections::HashMap;
use std::io::Write;
use std::str;
use std::sync::{
    mpsc::{channel, Receiver, Sender},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{task, time::sleep};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};
use url::Url;

const MAX_CLIENT_MESSAGE_SIZE: usize = 4000000;
const PING_INTERVAL: u64 = 8;
const PONG_TIMEOUT: u64 = 10;

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

#[derive(Debug, Deserialize)]
struct ClientResult {
    node: Node,
    sig_chain_block_hash: String,
}

#[derive(Debug, Clone)]
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

type Channel<T> = (Sender<T>, Receiver<T>);

fn parse_client_address(address_str: &str) -> Result<([u8; SHA256_LEN], Vec<u8>, String), String> {
    let client_id = sha256_hash(address_str.as_bytes());
    let substrings: Vec<&str> = address_str.split(".").collect();
    let public_key_str = substrings.last().unwrap();
    let public_key = hex::decode(public_key_str)
        .map_err(|_| "Invalid public key string converting to hex".to_string())?;
    let identifier = substrings[..substrings.len() - 1].join(".");
    Ok((client_id, public_key, identifier))
}

fn get_or_compute_shared_key(
    remote_public_key: &[u8],
    curve_secret_key: &[u8],
    shared_keys: &Arc<Mutex<HashMap<String, [u8; SHARED_KEY_LEN]>>>,
) -> Result<[u8; SHARED_KEY_LEN], String> {
    let remote_public_key_str = str::from_utf8(remote_public_key).unwrap();
    let shared_keys_lock = shared_keys.lock().unwrap();

    if let Some(shared_key) = shared_keys_lock.get(remote_public_key_str) {
        Ok(*shared_key)
    } else {
        drop(shared_keys_lock);

        if remote_public_key.len() != PUBLIC_KEY_LEN {
            return Err("invalid public key size".into());
        }

        let curve_public_key = ed25519_public_key_to_curve25519_public_key(&remote_public_key);
        let shared_key = ed25519_exchange(&curve_public_key, curve_secret_key);

        shared_keys
            .lock()
            .unwrap()
            .insert(remote_public_key_str.into(), shared_key);

        Ok(shared_key)
    }
}

fn encrypt_payload(
    payload: MessagePayload,
    dests: &[String],
    curve_secret_key: &[u8],
    shared_keys: &Arc<Mutex<HashMap<String, [u8; SHARED_KEY_LEN]>>>,
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
            let shared_key =
                get_or_compute_shared_key(&dest_pubkey, curve_secret_key, shared_keys)?;

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
        let shared_key = get_or_compute_shared_key(&dest_pubkey, curve_secret_key, shared_keys)?;

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

fn decrypt_payload(
    msg: PayloadMessage,
    src_address: &str,
    curve_secret_key: &[u8],
    shared_keys: &Arc<Mutex<HashMap<String, [u8; SHARED_KEY_LEN]>>>,
) -> Result<Vec<u8>, String> {
    let encrypted_payload = msg.payload;
    let (_, src_pubkey, _) = parse_client_address(src_address)?;

    if !msg.encrypted_key.is_empty() {
        let shared_key = get_or_compute_shared_key(&src_pubkey, curve_secret_key, shared_keys)?;
        let key = aes_decrypt(&msg.encrypted_key, &shared_key, &msg.nonce[..IV_LEN]);
        let payload = aes_decrypt(&encrypted_payload, &key, &msg.nonce[IV_LEN..]);
        Ok(payload)
    } else {
        let shared_key = get_or_compute_shared_key(&src_pubkey, curve_secret_key, shared_keys)?;
        let payload = aes_decrypt(&encrypted_payload, &shared_key, &msg.nonce);
        Ok(payload)
    }
}

async fn write_message(data: &[u8]) -> Result<(), String> {
    todo!()
}

async fn process_dests(dests: &[&str], rpc_config: RPCConfig) -> Result<Vec<String>, String> {
    if dests.is_empty() {
        return Ok(Vec::new());
    }

    let mut processed_dests = Vec::new();

    for dest in dests {
        let mut address: Vec<String> = dest.split('.').map(|s| s.to_string()).collect();

        if address.last().unwrap().len() < 2 * PUBLIC_KEY_LEN {
            let res = get_registrant(address.last().unwrap(), rpc_config.clone()).await;

            let reg = match res {
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
    dests: &[String],
    payload: MessagePayload,
    encrypted: bool,
    curve_secret_key: &[u8],
    shared_keys: &Arc<Mutex<HashMap<String, [u8; SHARED_KEY_LEN]>>>,
) -> Result<Vec<Vec<u8>>, String> {
    if encrypted {
        Ok(encrypt_payload(
            payload,
            dests,
            curve_secret_key,
            shared_keys,
        )?)
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
    dests: &[&str],
    payloads: &[&[u8]],
    encrypted: bool,
    max_holding_seconds: u32,
    public_key: &[u8],
    private_key: &[u8],
    address_id: &[u8],
    node: &Arc<Mutex<Option<Node>>>,
    sig_chain_block_hash: &Arc<Mutex<Option<String>>>,
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

    let node_public_key = hex::decode(&node.lock().unwrap().as_ref().unwrap().pub_key).unwrap();
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
        src_id: address_id.to_vec(),
        src_pubkey: public_key.to_vec(),
        dest_id: Vec::new(),
        dest_pubkey: Vec::new(),
        elems: vec![sig_chain_element],
    };

    if let Some(sig_chain_block_hash) = &*sig_chain_block_hash.lock().unwrap() {
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

        let signature = ed25519_sign(private_key, &digest);
        signatures.push(signature.to_vec());
    }

    outbound_msg.signatures = signatures;
    outbound_msg.nonce = nonce;
    Ok(outbound_msg)
}

fn create_client_message(outbound_msg: &OutboundMessage) -> Result<ClientMessage, String> {
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
    dests: &[&str],
    payload: MessagePayload,
    encrypted: bool,
    max_holding_seconds: u32,
    ws_write_timeout: u64,
    public_key: &[u8],
    private_key: &[u8],
    address_id: &[u8],
    curve_secret_key: &[u8],
    node: &Arc<Mutex<Option<Node>>>,
    sig_chain_block_hash: &Arc<Mutex<Option<String>>>,
    shared_keys: &Arc<Mutex<HashMap<String, [u8; SHARED_KEY_LEN]>>>,
    rpc_config: RPCConfig,
) -> Result<(), String> {
    let dests = process_dests(dests, rpc_config).await?;

    if dests.is_empty() {
        return Ok(());
    }

    let payloads = create_payloads(&dests, payload, encrypted, curve_secret_key, shared_keys)?;

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
                outbound_msgs.push(create_outbound_message(
                    &dest_list,
                    &payload_list,
                    encrypted,
                    max_holding_seconds,
                    public_key,
                    private_key,
                    address_id,
                    node,
                    sig_chain_block_hash,
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

    outbound_msgs.push(create_outbound_message(
        &dest_list,
        &payload_list,
        encrypted,
        max_holding_seconds,
        public_key,
        private_key,
        address_id,
        node,
        sig_chain_block_hash,
    )?);

    if outbound_msgs.len() > 1 {
        log::info!(
            "Client message size is greater than {} bytes, split into {} batches.",
            MAX_CLIENT_MESSAGE_SIZE,
            outbound_msgs.len()
        );
    }

    for outbound_msg in outbound_msgs {
        let client_msg = create_client_message(&outbound_msg)?;
        write_message(&serde_json::to_vec(&client_msg).unwrap()).await;
    }

    Ok(())
}

async fn send_receipt(prev_signature: &[u8], private_key: &[u8]) -> Result<(), String> {
    let sig_chain_element = SigChainElement {
        id: Vec::new(),
        next_pubkey: Vec::new(),
        mining: false,
        signature: Vec::new(),
        sig_algo: SigAlgo::Signature,
        vrf: Vec::new(),
        proof: Vec::new(),
    };
    let sig_chain_element_ser = sig_chain_element.serialize_unsigned();

    let mut digest = sha256_hash(&prev_signature).to_vec();
    digest.extend_from_slice(&sig_chain_element_ser);
    let digest = sha256_hash(&digest);
    let signature = ed25519_sign(&private_key, &digest);

    let receipt = Receipt {
        prev_hash: prev_signature.to_vec(),
        signature: signature.to_vec(),
    };
    let receipt_data = serde_json::to_vec(&receipt).unwrap();

    let client_msg = ClientMessage {
        message_type: ClientMessageType::Receipt,
        message: receipt_data,
        compression_type: CompressionType::CompressionNone,
    };
    let client_msg_data = serde_json::to_vec(&client_msg).unwrap();

    write_message(&client_msg_data).await
}

async fn handle_message(
    is_text: bool,
    data: Vec<u8>,
    address: String,
    private_key: Vec<u8>,
    config: Arc<Mutex<ClientConfig>>,
    closed: Arc<Mutex<bool>>,
    client_node: Arc<Mutex<Option<Node>>>,
    sig_chain_block_hash: Arc<Mutex<Option<String>>>,
    wallet: Arc<Mutex<Wallet>>,
    connect_tx: Sender<Node>,
    message_tx: Sender<Message>,
    reconnect_tx: Sender<()>,
    reply_tx: Sender<Reply>,
    response_channels: Arc<Mutex<HashMap<String, Channel<Message>>>>,
    curve_secret_key: [u8; SHARED_KEY_LEN],
    shared_keys: Arc<Mutex<HashMap<String, [u8; SHARED_KEY_LEN]>>>,
) -> Result<(), String> {
    if *closed.lock().unwrap() {
        return Ok(());
    }

    if is_text {
        let msg: JsonValue = serde_json::from_slice(&data).unwrap();
        let action = msg["Action"].as_str().unwrap();
        let error: NKNError = NKNError::from(msg["Error"].as_i64().unwrap());

        if error != NKNError::Success {
            if error == NKNError::WrongNode {
                // let node: Node = serde_json::from_value(msg["Result"].clone()).unwrap();
                // let address = address.clone();
                // let config_clone = config.clone();
                // let closed_clone = closed.clone();
                // let client_node_clone = client_node.clone();
                // let sig_chain_block_hash_clone = sig_chain_block_hash.clone();
                // let wallet_clone = wallet.clone();
                // let connect_tx_clone = connect_tx.clone();
                // let message_tx_clone = message_tx.clone();
                // let reconnect_tx_clone = reconnect_tx.clone();
                // let response_channels_clone = response_channels.clone();
                // task::spawn(async move {
                //     let res = connect_to_node(
                //         node,
                //         address,
                //         config_clone,
                //         closed_clone,
                //         client_node_clone,
                //         sig_chain_block_hash_clone,
                //         wallet_clone,
                //         connect_tx_clone,
                //         message_tx_clone,
                //         reconnect_tx_clone,
                //         response_channels_clone,
                //     )
                //     .await;

                //     if res.is_err() {
                //         reconnect_tx_clone.send(()).unwrap();
                //     }
                // });
            } else if action == "setClient" {
                close(closed.clone());
            }

            return Err("Error".into());
        }

        match action {
            "setClient" => {
                let result: ClientResult = serde_json::from_value(msg["Result"].clone()).unwrap();
                *sig_chain_block_hash.lock().unwrap() = Some(result.sig_chain_block_hash);

                if *closed.lock().unwrap() {
                    return Ok(());
                }

                let node = client_node.lock().unwrap().clone().unwrap();
                connect_tx.send(node).unwrap();
            }
            "updateSigChainBlockHash" => {
                *sig_chain_block_hash.lock().unwrap() =
                    Some(msg["Result"].as_str().unwrap().to_string());
            }
            _ => (),
        }

        Ok(())
    } else {
        let client_msg: ClientMessage = serde_json::from_slice(&data).unwrap();
        match client_msg.message_type {
            ClientMessageType::InboundMessage => {
                let inbound_msg: InboundMessage =
                    serde_json::from_slice(&client_msg.message).unwrap();

                if !inbound_msg.prev_hash.is_empty() {
                    let prev_hash = inbound_msg.prev_hash;
                    task::spawn(async move {
                        send_receipt(&prev_hash, &private_key).await.unwrap();
                    });
                }

                let payload_msg: PayloadMessage =
                    serde_json::from_slice(&inbound_msg.payload).unwrap();
                let encrypted = payload_msg.encrypted;

                let payload_bytes = if encrypted {
                    decrypt_payload(
                        payload_msg,
                        &inbound_msg.src,
                        &curve_secret_key,
                        &shared_keys,
                    )?
                } else {
                    payload_msg.payload
                };

                let payload: MessagePayload = serde_json::from_slice(&payload_bytes).unwrap();

                let data = match payload.r#type {
                    MessagePayloadType::Text => {
                        let text_data: TextData = serde_json::from_slice(&payload.data).unwrap();
                        text_data.text.as_bytes().to_vec()
                    }
                    MessagePayloadType::Ack => Vec::new(),
                    _ => unreachable!(),
                };

                let msg = Message {
                    src: inbound_msg.src,
                    data,
                    r#type: payload.r#type as u32,
                    encrypted,
                    message_id: payload.message_id,
                    no_reply: payload.no_reply,
                    reply_tx: reply_tx.clone(),
                };

                if !payload.reply_to_id.is_empty() {
                    let mut response_channels = response_channels.lock().unwrap();
                    let msg_id_str = str::from_utf8(&payload.reply_to_id).unwrap().to_string();
                    let channel = response_channels.get(&msg_id_str);

                    match channel {
                        Some((response_tx, _)) => {
                            response_tx.send(msg).unwrap();
                            response_channels.remove(&msg_id_str);
                        }
                        None => (),
                    }

                    return Ok(());
                }

                if *closed.lock().unwrap() {
                    return Ok(());
                }

                message_tx.send(msg).unwrap();

                Ok(())
            }
            _ => Ok(()),
        }
    }
}

async fn connect_to_node(
    node: Node,
    address: String,
    private_key: Vec<u8>,
    config: Arc<Mutex<ClientConfig>>,
    closed: Arc<Mutex<bool>>,
    client_node: Arc<Mutex<Option<Node>>>,
    sig_chain_block_hash: Arc<Mutex<Option<String>>>,
    wallet: Arc<Mutex<Wallet>>,
    connect_tx: Sender<Node>,
    message_tx: Sender<Message>,
    reconnect_tx: Sender<()>,
    reply_tx: Sender<Reply>,
    response_channels: Arc<Mutex<HashMap<String, Channel<Message>>>>,
    curve_secret_key: [u8; SHARED_KEY_LEN],
    shared_keys: Arc<Mutex<HashMap<String, [u8; SHARED_KEY_LEN]>>>,
) -> Result<(), String> {
    let handle = if !node.rpc_addr.is_empty() {
        let node = node.clone();
        let config = config.clone();

        let handle = task::spawn(async move {
            let addr = format!("http://{}", node.rpc_addr);

            let ws_handshake_timeout = config.lock().unwrap().ws_handshake_timeout;
            let node_state = match get_node_state(RPCConfig {
                rpc_server_address: vec![addr.clone()],
                rpc_timeout: Duration::from_secs(ws_handshake_timeout),
                ..RPCConfig::default()
            })
            .await
            {
                Ok(node_state) => node_state,
                Err(_) => return None,
            };

            if node_state.sync_state != SyncState::PersistFinished.to_string() {
                return None;
            }

            Some(addr)
        });
        Some(handle)
    } else {
        None
    };

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();

    let url = Url::parse(&format!("ws://{}", node.addr)).unwrap();
    let (ws_stream, _) = connect_async(url).await.expect("Failed to connect");
    let (write, read) = ws_stream.split();

    let stdin_to_ws = stdin_rx.map(Ok).forward(write);
    let ws_to_stdout = {
        read.for_each(|message| async {
            let data = match message.unwrap() {
                WsMessage::Text(text) => {
                    let mut data = text.as_bytes().to_vec();
                    data.push(0);
                    data
                }
                WsMessage::Binary(mut data) => {
                    data.push(1);
                    data
                }
                _ => Vec::new(),
            };
            tokio::io::stdout().write_all(&data).await.unwrap();
        })
    };

    // *conn.lock().unwrap() = ;
    *client_node.lock().unwrap() = Some(node);

    match handle {
        Some(handle) => match handle.await.unwrap() {
            Some(rpc_addr) => {
                let rpc_server_address = if rpc_addr.is_empty() {
                    Vec::new()
                } else {
                    vec![rpc_addr]
                };

                let mut wallet = wallet.lock().unwrap();
                let config = wallet.config().clone();
                wallet.set_config(WalletConfig {
                    rpc_server_address,
                    password: String::new(),
                    master_key: Vec::new(),
                    scrypt: config.scrypt.clone(),
                    ..config
                });
            }
            None => (),
        },
        None => (),
    }

    let done = Arc::new(Mutex::new(false));

    let done_clone = done.clone();
    let stdin_tx_clone = stdin_tx.clone();
    let reconnect_tx_clone = reconnect_tx.clone();
    task::spawn(async move {
        loop {
            if *done_clone.lock().unwrap() {
                return;
            }

            sleep(Duration::from_secs(PING_INTERVAL)).await;

            let res = stdin_tx_clone.unbounded_send(WsMessage::Ping(Vec::new()));

            if let Err(err) = res {
                log::error!("Error: {}", err);
                reconnect_tx_clone.send(());
                return;
            }
        }
    });

    let address_clone = address.clone();
    let reconnect_tx_clone = reconnect_tx.clone();
    task::spawn(async move {
        let req_bytes = json!({
            "Action": "setClient",
            "Addr": address_clone,
        })
        .to_string()
        .as_bytes()
        .to_vec();

        let res = stdin_tx.unbounded_send(WsMessage::Binary(req_bytes));

        if let Err(err) = res {
            log::error!("Error: {}", err);
            reconnect_tx_clone.send(());
            return;
        }
    });

    let closed_clone = closed.clone();
    task::spawn(async move {
        let mut stdin = tokio::io::stdin();

        loop {
            if *closed_clone.lock().unwrap() {
                return;
            }

            let mut data = vec![0; MAX_CLIENT_MESSAGE_SIZE];
            let n = match stdin.read(&mut data).await {
                Ok(n) => n,
                Err(_) | Ok(0) => break,
            };
            data.truncate(n);

            let is_text = data.pop().unwrap() == 0;
            let connect_tx_clone = connect_tx.clone();
            let message_tx_clone = message_tx.clone();
            let reply_tx_clone = reply_tx.clone();
            let reconnect_tx_clone = reconnect_tx.clone();
            let res = handle_message(
                is_text,
                data,
                address.clone(),
                private_key.clone(),
                config.clone(),
                closed.clone(),
                client_node.clone(),
                sig_chain_block_hash.clone(),
                wallet.clone(),
                connect_tx_clone,
                message_tx_clone,
                reconnect_tx_clone,
                reply_tx_clone,
                response_channels.clone(),
                curve_secret_key.clone(),
                shared_keys.clone(),
            )
            .await;

            if let Err(err) = res {
                log::error!("Error: {}", err);
            }
        }

        *done.lock().unwrap() = true;
    });

    task::spawn(async move {
        pin_mut!(stdin_to_ws, ws_to_stdout);
        future::select(stdin_to_ws, ws_to_stdout).await;
    });

    Ok(())
}

async fn connect(
    max_retries: u32,
    address: String,
    private_key: Vec<u8>,
    config: Arc<Mutex<ClientConfig>>,
    closed: Arc<Mutex<bool>>,
    client_node: Arc<Mutex<Option<Node>>>,
    sig_chain_block_hash: Arc<Mutex<Option<String>>>,
    wallet: Arc<Mutex<Wallet>>,
    connect_tx: Sender<Node>,
    message_tx: Sender<Message>,
    reconnect_tx: Sender<()>,
    reply_tx: Sender<Reply>,
    response_channels: Arc<Mutex<HashMap<String, Channel<Message>>>>,
    curve_secret_key: [u8; SHARED_KEY_LEN],
    shared_keys: Arc<Mutex<HashMap<String, [u8; SHARED_KEY_LEN]>>>,
) -> Result<(), String> {
    let max_reconnect_interval = config.lock().unwrap().max_reconnect_interval;

    let mut retry_interval = config.lock().unwrap().min_reconnect_interval;
    let mut retry = 0;

    while max_retries == 0 || retry < max_retries {
        if retry > 0 {
            log::info!("Retry in {} ms...", retry_interval);
            sleep(Duration::from_millis(retry_interval)).await;

            retry_interval *= 2;
            if retry_interval > max_reconnect_interval {
                retry_interval = max_reconnect_interval;
            }
        }

        let rpc_config = client_config_to_rpc_config(&config.lock().unwrap());
        let res = get_ws_address(&address, rpc_config).await;

        match res {
            Ok(node) => {
                let connect_tx_clone = connect_tx.clone();
                let message_tx_clone = message_tx.clone();
                let reply_tx_clone = reply_tx.clone();
                let reconnect_tx_clone = reconnect_tx.clone();
                let res = connect_to_node(
                    node,
                    address.clone(),
                    private_key.clone(),
                    config.clone(),
                    closed.clone(),
                    client_node.clone(),
                    sig_chain_block_hash.clone(),
                    wallet.clone(),
                    connect_tx_clone,
                    message_tx_clone,
                    reconnect_tx_clone,
                    reply_tx_clone,
                    response_channels.clone(),
                    curve_secret_key.clone(),
                    shared_keys.clone(),
                )
                .await;

                match res {
                    Ok(()) => return Ok(()),
                    Err(err) => log::error!("Error: {}", err),
                }
            }
            Err(err) => log::error!("Error: {}", err),
        }

        retry += 1;
    }

    Err("connect failed".into())
}

fn close(closed: Arc<Mutex<bool>>) {
    *closed.lock().unwrap() = true;
    todo!(); // close connection
}

async fn handle_reconnect(
    reconnect_rx: Receiver<()>,
    address: String,
    private_key: Vec<u8>,
    config: Arc<Mutex<ClientConfig>>,
    closed: Arc<Mutex<bool>>,
    client_node: Arc<Mutex<Option<Node>>>,
    sig_chain_block_hash: Arc<Mutex<Option<String>>>,
    wallet: Arc<Mutex<Wallet>>,
    connect_tx: Sender<Node>,
    message_tx: Sender<Message>,
    reconnect_tx: Sender<()>,
    reply_tx: Sender<Reply>,
    response_channels: Arc<Mutex<HashMap<String, Channel<Message>>>>,
    curve_secret_key: [u8; SHARED_KEY_LEN],
    shared_keys: Arc<Mutex<HashMap<String, [u8; SHARED_KEY_LEN]>>>,
) {
    loop {
        reconnect_rx.recv().unwrap();

        if *closed.lock().unwrap() {
            return;
        }

        let min_reconnect_interval = config.lock().unwrap().min_reconnect_interval;
        log::info!("Reconnect in {} ms...", min_reconnect_interval);
        sleep(Duration::from_millis(min_reconnect_interval)).await;

        let connect_tx_clone = connect_tx.clone();
        let message_tx_clone = message_tx.clone();
        let reply_tx_clone = reply_tx.clone();
        let reconnect_tx_clone = reconnect_tx.clone();
        let res = connect(
            0,
            address.clone(),
            private_key.clone(),
            config.clone(),
            closed.clone(),
            client_node.clone(),
            sig_chain_block_hash.clone(),
            wallet.clone(),
            connect_tx_clone,
            message_tx_clone,
            reconnect_tx_clone,
            reply_tx_clone,
            response_channels.clone(),
            curve_secret_key.clone(),
            shared_keys.clone(),
        )
        .await;

        if let Err(err) = res {
            log::error!("Error: {}", err);
            close(closed.clone());
        }
    }
}

async fn handle_reply(
    reply_rx: Receiver<Reply>,
    ws_write_timeout: u64,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    address_id: [u8; SHA256_LEN],
    curve_secret_key: [u8; SHARED_KEY_LEN],
    node: Arc<Mutex<Option<Node>>>,
    sig_chain_block_hash: Arc<Mutex<Option<String>>>,
    shared_keys: Arc<Mutex<HashMap<String, [u8; SHARED_KEY_LEN]>>>,
    rpc_config: RPCConfig,
) {
    loop {
        let (src, payload, encrypted) = reply_rx.recv().unwrap();

        let res = send_messages(
            &[src.as_str()],
            payload,
            encrypted,
            0,
            ws_write_timeout,
            &public_key,
            &private_key,
            &address_id,
            &curve_secret_key,
            &node,
            &sig_chain_block_hash,
            &shared_keys,
            rpc_config.clone(),
        )
        .await;

        if let Err(err) = res {
            log::error!("Error: {}", err);
        }
    }
}

pub struct Client {
    config: Arc<Mutex<ClientConfig>>,
    wallet: Arc<Mutex<Wallet>>,
    account: Account,
    address: String,
    address_id: [u8; SHA256_LEN],
    curve_secret_key: [u8; SHARED_KEY_LEN],
    closed: Arc<Mutex<bool>>,
    node: Arc<Mutex<Option<Node>>>,
    sig_chain_block_hash: Arc<Mutex<Option<String>>>,
    connect_channel: Channel<Node>,
    message_channel: Channel<Message>,
    reconnect_tx: Sender<()>,
    reply_tx: Sender<Reply>,
    response_channels: Arc<Mutex<HashMap<String, Channel<Message>>>>,
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

        let config = Arc::new(Mutex::new(config));
        let closed = Arc::new(Mutex::new(false));
        let node = Arc::new(Mutex::new(None));
        let sig_chain_block_hash = Arc::new(Mutex::new(None));
        let wallet = Arc::new(Mutex::new(wallet));
        let response_channels = Arc::new(Mutex::new(HashMap::new()));
        let shared_keys = Arc::new(Mutex::new(HashMap::new()));

        let (connect_tx, connect_rx) = channel();
        let (message_tx, message_rx) = channel();
        let (reply_tx, reply_rx) = channel();
        let (reconnect_tx, reconnect_rx) = channel();

        let address_clone = address.clone();
        let private_key = account.private_key().to_vec();
        let config_clone = config.clone();
        let closed_clone = closed.clone();
        let node_clone = node.clone();
        let sig_chain_block_hash_clone = sig_chain_block_hash.clone();
        let wallet_clone = wallet.clone();
        let connect_tx_clone = connect_tx.clone();
        let message_tx_clone = message_tx.clone();
        let reconnect_tx_clone = reconnect_tx.clone();
        let reply_tx_clone = reply_tx.clone();
        let response_channels_clone = response_channels.clone();
        let curve_secret_key_clone = curve_secret_key.clone();
        let shared_keys_clone = shared_keys.clone();
        task::spawn(async move {
            handle_reconnect(
                reconnect_rx,
                address_clone,
                private_key,
                config_clone,
                closed_clone,
                node_clone,
                sig_chain_block_hash_clone,
                wallet_clone,
                connect_tx_clone,
                message_tx_clone,
                reconnect_tx_clone,
                reply_tx_clone,
                response_channels_clone,
                curve_secret_key_clone,
                shared_keys_clone,
            )
            .await;
        });

        let address_clone = address.clone();
        let private_key = account.private_key().to_vec();
        let config_clone = config.clone();
        let closed_clone = closed.clone();
        let node_clone = node.clone();
        let sig_chain_block_hash_clone = sig_chain_block_hash.clone();
        let wallet_clone = wallet.clone();
        let connect_tx_clone = connect_tx.clone();
        let message_tx_clone = message_tx.clone();
        let reconnect_tx_clone = reconnect_tx.clone();
        let reply_tx_clone = reply_tx.clone();
        let response_channels_clone = response_channels.clone();
        let curve_secret_key_clone = curve_secret_key.clone();
        let shared_keys_clone = shared_keys.clone();
        task::spawn(async move {
            connect(
                0,
                address_clone,
                private_key,
                config_clone,
                closed_clone,
                node_clone,
                sig_chain_block_hash_clone,
                wallet_clone,
                connect_tx_clone,
                message_tx_clone,
                reconnect_tx_clone,
                reply_tx_clone,
                response_channels_clone,
                curve_secret_key_clone,
                shared_keys_clone,
            )
            .await
            .unwrap();
        });

        let ws_write_timeout = config.lock().unwrap().ws_write_timeout;
        let public_key = account.public_key().to_vec();
        let private_key = account.private_key().to_vec();
        let address_id_clone = address_id.clone();
        let curve_secret_key_clone = curve_secret_key.clone();
        let node_clone = node.clone();
        let sig_chain_block_hash_clone = sig_chain_block_hash.clone();
        let shared_keys_clone = shared_keys.clone();
        let rpc_config = client_config_to_rpc_config(&config.lock().unwrap());
        task::spawn(async move {
            handle_reply(
                reply_rx,
                ws_write_timeout,
                public_key,
                private_key,
                address_id_clone,
                curve_secret_key_clone,
                node_clone,
                sig_chain_block_hash_clone,
                shared_keys_clone,
                rpc_config,
            )
            .await;
        });

        Ok(Self {
            config,
            account,
            address,
            address_id,
            curve_secret_key,
            wallet,
            closed,
            node,
            sig_chain_block_hash,
            connect_channel: (connect_tx, connect_rx),
            message_channel: (message_tx, message_rx),
            reconnect_tx,
            reply_tx,
            response_channels,
            shared_keys,
        })
    }

    pub fn config(&self) -> ClientConfig {
        self.config.lock().unwrap().clone()
    }

    pub fn set_config(&mut self, config: ClientConfig) {
        *self.config.lock().unwrap() = config;
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
        close(self.closed.clone());
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
        let (connect_tx, _) = &self.connect_channel;
        let (message_tx, _) = &self.message_channel;

        connect(
            max_retries,
            self.address.clone(),
            self.private_key().to_vec(),
            self.config.clone(),
            self.closed.clone(),
            self.node.clone(),
            self.sig_chain_block_hash.clone(),
            self.wallet.clone(),
            connect_tx.clone(),
            message_tx.clone(),
            self.reconnect_tx.clone(),
            self.reply_tx.clone(),
            self.response_channels.clone(),
            self.curve_secret_key.clone(),
            self.shared_keys.clone(),
        )
        .await
    }

    pub async fn reconnect(&mut self) -> Result<(), String> {
        if *self.closed.lock().unwrap() {
            return Ok(());
        }

        self.reconnect_tx.send(());

        Ok(())
    }

    pub fn node(&self) -> Option<Node> {
        self.node.lock().unwrap().clone()
    }

    async fn send_messages(
        &self,
        dests: &[&str],
        payload: MessagePayload,
        encrypted: bool,
        max_holding_seconds: u32,
        ws_write_timeout: u64,
    ) -> Result<(), String> {
        send_messages(
            dests,
            payload,
            encrypted,
            max_holding_seconds,
            ws_write_timeout,
            self.public_key(),
            self.private_key(),
            &self.address_id,
            &self.curve_secret_key,
            &self.node,
            &self.sig_chain_block_hash,
            &self.shared_keys,
            client_config_to_rpc_config(&self.config.lock().unwrap()),
        )
        .await
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
            self.config.lock().unwrap().ws_write_timeout,
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

    async fn send(
        &mut self,
        dests: &[&str],
        payload: MessagePayload,
        config: MessageConfig,
    ) -> Result<(), String> {
        let message_id = payload.message_id.clone();

        self.send_messages(
            dests,
            payload,
            !config.unencrypted,
            config.max_holding_seconds,
            self.config.lock().unwrap().ws_write_timeout,
        )
        .await?;

        if !config.no_reply {
            let message_id = str::from_utf8(&message_id).unwrap();
            self.response_channels
                .lock()
                .unwrap()
                .insert(message_id.into(), channel());
        }

        Ok(())
    }

    pub async fn send_binary(
        &mut self,
        dests: &[&str],
        data: &[u8],
        config: MessageConfig,
    ) -> Result<(), String> {
        let payload = MessagePayload::new_binary(data, &config.message_id, &[], true);
        self.send(dests, payload, config).await
    }

    pub async fn send_text(
        &mut self,
        dests: &[&str],
        text: &str,
        config: MessageConfig,
    ) -> Result<(), String> {
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
            client_config_to_rpc_config(&self.config.lock().unwrap()),
            self.wallet.lock().unwrap().clone(),
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
            self.wallet.lock().unwrap().address()
        } else {
            recipient_address.into()
        };
        NanoPayClaimer::new(
            client_config_to_rpc_config(&self.config.lock().unwrap()),
            &recipient_address,
            claim_interval_ms,
            min_flush_amount,
        )
    }

    pub fn sign_transaction(&self, tx: &mut Transaction) {
        self.wallet.lock().unwrap().sign_transaction(tx);
    }

    pub async fn nonce(&self, tx_pool: bool) -> Result<u64, String> {
        self.nonce_by_address(&self.wallet.lock().unwrap().address(), tx_pool)
            .await
    }

    pub async fn nonce_by_address(&self, address: &str, tx_pool: bool) -> Result<u64, String> {
        let wallet = self.wallet.lock().unwrap();
        let wallet_config = wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_nonce(
                address,
                tx_pool,
                client_config_to_rpc_config(&self.config.lock().unwrap()),
            )
            .await
        } else {
            get_nonce(address, tx_pool, wallet_config_to_rpc_config(wallet_config)).await
        }
    }

    pub async fn balance(&self) -> Result<i64, String> {
        self.balance_by_address(&self.wallet.lock().unwrap().address())
            .await
    }

    pub async fn balance_by_address(&self, address: &str) -> Result<i64, String> {
        let wallet = self.wallet.lock().unwrap();
        let wallet_config = wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_balance(
                address,
                client_config_to_rpc_config(&self.config.lock().unwrap()),
            )
            .await
        } else {
            get_balance(address, wallet_config_to_rpc_config(wallet_config)).await
        }
    }

    pub async fn height(&self) -> Result<u64, String> {
        let wallet = self.wallet.lock().unwrap();
        let wallet_config = wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_height(client_config_to_rpc_config(&self.config.lock().unwrap())).await
        } else {
            get_height(wallet_config_to_rpc_config(wallet_config)).await
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
        let wallet = self.wallet.lock().unwrap();
        let wallet_config = wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_subscribers(
                topic,
                offset,
                limit,
                meta,
                tx_pool,
                client_config_to_rpc_config(&self.config.lock().unwrap()),
            )
            .await
        } else {
            get_subscribers(
                topic,
                offset,
                limit,
                meta,
                tx_pool,
                wallet_config_to_rpc_config(wallet_config),
            )
            .await
        }
    }

    pub async fn subscription(
        &self,
        topic: &str,
        subscriber: &str,
    ) -> Result<Subscription, String> {
        let wallet = self.wallet.lock().unwrap();
        let wallet_config = wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_subscription(
                topic,
                subscriber,
                client_config_to_rpc_config(&self.config.lock().unwrap()),
            )
            .await
        } else {
            get_subscription(
                topic,
                subscriber,
                wallet_config_to_rpc_config(wallet_config),
            )
            .await
        }
    }

    pub async fn suscribers_count(
        &self,
        topic: &str,
        subscriber_hash_prefix: &[u8],
    ) -> Result<u32, String> {
        let wallet = self.wallet.lock().unwrap();
        let wallet_config = wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_subscribers_count(
                topic,
                subscriber_hash_prefix,
                client_config_to_rpc_config(&self.config.lock().unwrap()),
            )
            .await
        } else {
            get_subscribers_count(
                topic,
                subscriber_hash_prefix,
                wallet_config_to_rpc_config(wallet_config),
            )
            .await
        }
    }

    pub async fn registrant(&self, name: &str) -> Result<Registrant, String> {
        let wallet = self.wallet.lock().unwrap();
        let wallet_config = wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            get_registrant(
                name,
                client_config_to_rpc_config(&self.config.lock().unwrap()),
            )
            .await
        } else {
            get_registrant(name, wallet_config_to_rpc_config(wallet_config)).await
        }
    }

    pub async fn send_raw_transaction(&self, txn: &Transaction) -> Result<String, String> {
        let wallet = self.wallet.lock().unwrap();
        let wallet_config = wallet.config();
        if wallet_config.rpc_server_address.is_empty() {
            send_raw_transaction(
                txn,
                client_config_to_rpc_config(&self.config.lock().unwrap()),
            )
            .await
        } else {
            send_raw_transaction(txn, wallet_config_to_rpc_config(wallet_config)).await
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

        let mut tx =
            Transaction::new_transfer_asset(&sender, &recipient, nonce, amount, config.fee);

        if config.attributes.len() > 0 {
            tx.unsigned_tx.attributes = config.attributes;
        }

        self.sign_transaction(&mut tx);
        self.send_raw_transaction(&tx).await
    }

    pub async fn register_name(
        &self,
        name: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
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

    pub async fn delete_name(
        &self,
        name: &str,
        config: TransactionConfig,
    ) -> Result<String, String> {
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

        let mut tx =
            Transaction::new_unsubscribe(self.public_key(), identifier, topic, nonce, config.fee);

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
