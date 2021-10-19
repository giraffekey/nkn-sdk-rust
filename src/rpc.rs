use crate::constant::{DEFAULT_RPC_CONCURRENCY, DEFAULT_RPC_TIMEOUT, MIN_NAME_REGISTRATION_FEE};
use crate::program::{create_program_hash, to_script_hash};
use crate::signature::Signer;
use crate::transaction::{Transaction, TransactionConfig};

use async_trait::async_trait;
use hyper::{body, client::HttpConnector, Body, Client, Method, Request};
use hyper_tls::HttpsConnector;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use std::{
    collections::HashMap,
    str,
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};
use tokio::task;

#[async_trait]
pub trait RPCClient {
    async fn nonce(&self, tx_pool: bool) -> Result<u64, String>;
    async fn nonce_by_address(&self, address: &str, tx_pool: bool) -> Result<u64, String>;
    async fn balance(&self) -> Result<i64, String>;
    async fn balance_by_address(&self, address: &str) -> Result<i64, String>;
    async fn height(&self) -> Result<u64, String>;
    async fn subscribers(
        &self,
        topic: &str,
        offset: u32,
        limit: u32,
        meta: bool,
        tx_pool: bool,
    ) -> Result<Subscribers, String>;
    async fn subscription(&self, topic: &str, subscriber: &str) -> Result<Subscription, String>;
    async fn suscribers_count(
        &self,
        topic: &str,
        subscriber_hash_prefix: &[u8],
    ) -> Result<u32, String>;
    async fn registrant(&self, name: &str) -> Result<Registrant, String>;
    async fn send_raw_transaction(&self, txn: &Transaction) -> Result<String, String>;
}

#[async_trait]
pub trait SignerRPCClient: Signer + RPCClient {
    fn sign_transaction(&self, tx: &mut Transaction);
    async fn transfer(
        &self,
        address: &str,
        amount: i64,
        config: TransactionConfig,
    ) -> Result<String, String>;
    async fn register_name(&self, name: &str, config: TransactionConfig) -> Result<String, String>;
    async fn transfer_name(
        &self,
        name: &str,
        recipient_public_key: &[u8],
        config: TransactionConfig,
    ) -> Result<String, String>;
    async fn delete_name(&self, name: &str, config: TransactionConfig) -> Result<String, String>;
    async fn subscribe(
        &self,
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        config: TransactionConfig,
    ) -> Result<String, String>;
    async fn unsubscribe(
        &self,
        identifier: &str,
        topic: &str,
        config: TransactionConfig,
    ) -> Result<String, String>;
}

#[derive(Debug)]
pub struct RPCConfig {
    pub rpc_server_address: Vec<String>,
    pub rpc_timeout: Duration,
    pub rpc_concurrency: u32,
}

impl Default for RPCConfig {
    fn default() -> Self {
        Self {
            rpc_server_address: Vec::new(),
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            rpc_concurrency: DEFAULT_RPC_CONCURRENCY,
        }
    }
}

#[derive(Deserialize)]
struct RPCError {
    code: i32,
    message: String,
    data: String,
}

#[derive(Deserialize)]
struct RPCResponse<D> {
    result: Option<D>,
    error: Option<RPCError>,
}

async fn request<D: DeserializeOwned>(
    client: &Client<HttpsConnector<HttpConnector>>,
    address: &str,
    body: String,
) -> Result<D, String> {
    let req = Request::builder()
        .method(Method::POST)
        .uri(address)
        .body(Body::from(body))
        .unwrap();

    let res = client
        .request(req)
        .await
        .map_err(|err| format!("Client: {:?}", err))?;
    let body = body::to_bytes(res.into_body())
        .await
        .map_err(|err| format!("Body: {:?}", err))?;
    let body_str = str::from_utf8(&body).map_err(|err| format!("Body: {:?}", err))?;
    let res: RPCResponse<D> =
        serde_json::from_str(body_str).map_err(|err| format!("Json: {:?}", err))?;
    if let Some(err) = res.error {
        return Err(format!("{}: {}", err.message, err.data));
    }
    Ok(res.result.unwrap())
}

pub async fn rpc_call<S: Serialize, D: DeserializeOwned + Send + 'static>(
    method: &str,
    params: S,
    config: RPCConfig,
) -> Result<D, String> {
    if config.rpc_server_address.is_empty() {
        return Err("No server addresses in config".into());
    }

    let https = HttpsConnector::new();
    let client = Client::builder()
        .pool_idle_timeout(config.rpc_timeout)
        .build::<_, Body>(https);

    let body = json!({
        "id": "nkn-sdk-go",
        "method": method,
        "params": params,
    })
    .to_string();

    let result: Arc<Mutex<Result<D, String>>> = Arc::new(Mutex::new(Err("couldn't find".into())));

    let n = if config.rpc_concurrency > 0 {
        config.rpc_concurrency as usize
    } else {
        config.rpc_server_address.len()
    };

    let mut join_handles = Vec::new();

    for i in 0..n {
        let (left, right) = config
            .rpc_server_address
            .split_at(i % config.rpc_server_address.len());
        let addresses = [right, left].concat();
        let result = result.clone();
        let client = client.clone();
        let body = body.clone();

        join_handles.push(task::spawn(async move {
            for address in &addresses {
                if result.lock().unwrap().is_ok() {
                    return;
                }

                let res = request(&client, &address, body.clone()).await;

                let mut lock = result.lock().unwrap();
                if lock.is_err() {
                    *lock = res;
                }
            }
        }));
    }

    for join_handle in join_handles.drain(..) {
        join_handle.await.unwrap();
    }

    Arc::try_unwrap(result)
        .map_err(|_| "couldn't unwrap")?
        .into_inner()
        .unwrap()
}

#[derive(Debug, Deserialize)]
pub struct Node {
    pub address: String,
    pub rpc_address: String,
    pub public_key: Vec<u8>,
    pub id: String,
}

pub async fn get_ws_address(client_address: &str, config: RPCConfig) -> Result<Node, String> {
    rpc_call("getwsaddr", json!({ "address": client_address }), config).await
}

pub async fn get_wss_address(client_address: &str, config: RPCConfig) -> Result<Node, String> {
    rpc_call("getwssaddr", json!({ "address": client_address }), config).await
}

#[derive(Debug)]
pub enum SyncState {
    WaitForSyncing = 0,
    SyncStarted = 1,
    SyncFinished = 2,
    PersistFinished = 3,
}

impl ToString for SyncState {
    fn to_string(&self) -> String {
        match self {
            WaitForSyncing => "WAIT_FOR_SYNCING".into(),
            SyncStarted => "SYNC_STARTED".into(),
            SyncFinished => "SYNC_FINISHED".into(),
            PersistFinished => "PERSIST_FINISHED".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NodeState {
    pub address: String,
    pub current_timestamp: u64,
    pub height: u32,
    pub id: String,
    pub json_rpc_port: u32,
    pub proposal_submitted: u32,
    pub protocol_version: u32,
    pub public_key: Vec<u8>,
    pub relay_message_count: u64,
    pub sync_state: String,
    pub tls_json_rpc_domain: String,
    pub tls_json_rpc_port: u32,
    pub tls_websocket_domain: String,
    pub tls_websocket_port: u32,
    pub uptime: u64,
    pub version: String,
    pub websocket_port: u32,
}

pub async fn get_node_state(config: RPCConfig) -> Result<NodeState, String> {
    rpc_call("getnodestate", json!({}), config).await
}

#[derive(Debug, Deserialize)]
pub struct Subscription {
    pub meta: String,
    pub expires_at: u64,
}

pub async fn get_subscription(
    topic: &str,
    subscriber: &str,
    config: RPCConfig,
) -> Result<Subscription, String> {
    rpc_call(
        "getsubscription",
        json!({
            "topic": topic,
            "subscriber": subscriber,
        }),
        config,
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct Subscribers {
    pub subscribers: HashMap<String, String>,
    pub subscribers_in_tx_pool: HashMap<String, String>,
}

pub async fn get_subscribers(
    topic: &str,
    offset: u32,
    limit: u32,
    meta: bool,
    tx_pool: bool,
    config: RPCConfig,
) -> Result<Subscribers, String> {
    let subscribers: JsonValue = rpc_call(
        "getsubscribers",
        json!({
            "topic": topic,
            "offset": offset,
            "limit": limit,
            "meta": meta,
            "txPool": tx_pool,
        }),
        config,
    )
    .await?;

    if meta {
        Ok(Subscribers {
            subscribers: subscribers["subscribers"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(subscriber, meta)| (subscriber.clone(), meta.as_str().unwrap().into()))
                .collect(),
            subscribers_in_tx_pool: if tx_pool {
                subscribers["subscribersInTxPool"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(subscriber, meta)| (subscriber.clone(), meta.as_str().unwrap().into()))
                    .collect()
            } else {
                HashMap::new()
            },
        })
    } else {
        Ok(Subscribers {
            subscribers: subscribers["subscribers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|subscriber| (subscriber.as_str().unwrap().into(), "".into()))
                .collect(),
            subscribers_in_tx_pool: if tx_pool {
                subscribers["subscribersInTxPool"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|subscriber| (subscriber.as_str().unwrap().into(), "".into()))
                    .collect()
            } else {
                HashMap::new()
            },
        })
    }
}

pub async fn get_subscribers_count(
    topic: &str,
    subscriber_hash_prefix: &[u8],
    config: RPCConfig,
) -> Result<u32, String> {
    rpc_call("getsubscriberscount", json!({ "topic": topic }), config).await
}

#[derive(Debug, Deserialize)]
pub struct Registrant {
    pub registrant: String,
    pub expires_at: u64,
}

pub async fn get_registrant(name: &str, config: RPCConfig) -> Result<Registrant, String> {
    rpc_call("getregistrant", json!({ "name": name }), config).await
}

#[derive(Debug, Deserialize, Serialize)]
struct Nonce {
    pub nonce: u64,
    pub nonce_in_tx_pool: u64,
}

pub async fn get_nonce(address: &str, tx_pool: bool, config: RPCConfig) -> Result<u64, String> {
    let nonce: Nonce = rpc_call("getnoncebyaddr", json!({ "address": address }), config).await?;

    if tx_pool && nonce.nonce_in_tx_pool > nonce.nonce {
        Ok(nonce.nonce_in_tx_pool)
    } else {
        Ok(nonce.nonce)
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Balance {
    pub amount: i64,
}

pub async fn get_balance(address: &str, config: RPCConfig) -> Result<i64, String> {
    let balance: Balance =
        rpc_call("getbalancebyaddr", json!({ "address": address }), config).await?;
    Ok(balance.amount)
}

pub async fn get_height(config: RPCConfig) -> Result<u64, String> {
    rpc_call("getlatestblockheight", json!({}), config).await
}

pub async fn send_raw_transaction(tx: &Transaction, config: RPCConfig) -> Result<String, String> {
    let tx_hex: String = hex::encode(serde_json::to_string(tx).unwrap());
    rpc_call("sendrawtransaction", json!({ "tx": tx_hex }), config).await
}

pub async fn transfer<S: SignerRPCClient>(
    s: &S,
    address: &str,
    amount: i64,
    config: TransactionConfig,
) -> Result<String, String> {
    let sender = create_program_hash(s.public_key());
    let recipient = to_script_hash(address)?;

    let nonce = if config.nonce > 0 {
        config.nonce
    } else {
        s.nonce(true).await?
    };

    let mut tx = Transaction::new_transfer_asset(&sender, &recipient, nonce, amount, config.fee);

    if config.attributes.len() > 0 {
        tx.unsigned_tx.attributes = config.attributes;
    }

    s.sign_transaction(&mut tx);
    s.send_raw_transaction(&tx).await
}

pub async fn register_name<S: SignerRPCClient>(
    s: &S,
    name: &str,
    config: TransactionConfig,
) -> Result<String, String> {
    let nonce = if config.nonce > 0 {
        config.nonce
    } else {
        s.nonce(true).await?
    };

    let mut tx = Transaction::new_register_name(
        s.public_key(),
        name,
        nonce,
        MIN_NAME_REGISTRATION_FEE,
        config.fee,
    );

    if config.attributes.len() > 0 {
        tx.unsigned_tx.attributes = config.attributes;
    }

    s.sign_transaction(&mut tx);
    s.send_raw_transaction(&tx).await
}

pub async fn transfer_name<S: SignerRPCClient>(
    s: &S,
    name: &str,
    recipient_public_key: &[u8],
    config: TransactionConfig,
) -> Result<String, String> {
    let nonce = if config.nonce > 0 {
        config.nonce
    } else {
        s.nonce(true).await?
    };

    let mut tx = Transaction::new_transfer_name(
        s.public_key(),
        recipient_public_key,
        name,
        nonce,
        config.fee,
    );

    if config.attributes.len() > 0 {
        tx.unsigned_tx.attributes = config.attributes;
    }

    s.sign_transaction(&mut tx);
    s.send_raw_transaction(&tx).await
}

pub async fn delete_name<S: SignerRPCClient>(
    s: &S,
    name: &str,
    config: TransactionConfig,
) -> Result<String, String> {
    let nonce = if config.nonce > 0 {
        config.nonce
    } else {
        s.nonce(true).await?
    };

    let mut tx = Transaction::new_delete_name(s.public_key(), name, nonce, config.fee);

    if config.attributes.len() > 0 {
        tx.unsigned_tx.attributes = config.attributes;
    }

    s.sign_transaction(&mut tx);
    s.send_raw_transaction(&tx).await
}

pub async fn subscribe<S: SignerRPCClient>(
    s: &S,
    identifier: &str,
    topic: &str,
    duration: u32,
    meta: &str,
    config: TransactionConfig,
) -> Result<String, String> {
    let nonce = if config.nonce > 0 {
        config.nonce
    } else {
        s.nonce(true).await?
    };

    let mut tx = Transaction::new_subscribe(
        s.public_key(),
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

    s.sign_transaction(&mut tx);
    s.send_raw_transaction(&tx).await
}

pub async fn unsubscribe<S: SignerRPCClient>(
    s: &S,
    identifier: &str,
    topic: &str,
    config: TransactionConfig,
) -> Result<String, String> {
    let nonce = if config.nonce > 0 {
        config.nonce
    } else {
        s.nonce(true).await?
    };

    let mut tx = Transaction::new_unsubscribe(s.public_key(), identifier, topic, nonce, config.fee);

    if config.attributes.len() > 0 {
        tx.unsigned_tx.attributes = config.attributes;
    }

    s.sign_transaction(&mut tx);
    s.send_raw_transaction(&tx).await
}

pub async fn measure_rpc_server(
    rpc_list: &[&str],
    timeout: Duration,
) -> Result<Vec<String>, String> {
    let (tx, rx) = mpsc::channel();

    for address in rpc_list {
        let timeout = timeout.clone();
        let address = address.to_string();
        let tx = tx.clone();

        task::spawn(async move {
            let node_state = match get_node_state(RPCConfig {
                rpc_server_address: vec![address.clone()],
                rpc_timeout: timeout,
                ..RPCConfig::default()
            })
            .await
            {
                Ok(node_state) => node_state,
                Err(err) => {
                    tx.send(None).unwrap();
                    return;
                }
            };

            if node_state.sync_state == SyncState::PersistFinished.to_string() {
                tx.send(Some(address)).unwrap();
            } else {
                tx.send(None).unwrap();
            }
        });
    }

    let mut rpc_addrs = Vec::new();

    for _ in 0..rpc_list.len() {
        if let Some(address) = rx.recv().unwrap() {
            rpc_addrs.push(address);
        }
    }

    Ok(rpc_addrs)
}
