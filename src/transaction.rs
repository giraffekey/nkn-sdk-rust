use crate::crypto::sha256_hash;
use crate::program::{create_program_hash, Program};
use crate::signature::SignableData;
use crate::signature::{get_hash_data, verify_signable_data};

use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

const TX_NONCE_LEN: usize = 32;

#[derive(Debug)]
pub struct TransactionConfig {
    pub fee: i64,
    pub nonce: u64,
    pub attributes: Vec<u8>,
}

impl Default for TransactionConfig {
    fn default() -> Self {
        Self {
            fee: 0,
            nonce: 0,
            attributes: Vec::new(),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub enum Payload {
    Coinbase {
        sender: Vec<u8>,
        recipient: Vec<u8>,
        amount: i64,
    },
    TransferAsset {
        sender: Vec<u8>,
        recipient: Vec<u8>,
        amount: i64,
    },
    SigChain {
        sigchain: Vec<u8>,
        submitter: Vec<u8>,
    },
    RegisterName {
        registrant: Vec<u8>,
        name: String,
        fee: i64,
    },
    TransferName {
        registrant: Vec<u8>,
        recipient: Vec<u8>,
        name: String,
    },
    DeleteName {
        registrant: Vec<u8>,
        name: String,
    },
    Subscribe {
        subscriber: Vec<u8>,
        identifier: String,
        topic: String,
        duration: u32,
        meta: String,
    },
    Unsubscribe {
        subscriber: Vec<u8>,
        identifier: String,
        topic: String,
    },
    GenerateId {
        publickey: Vec<u8>,
        sender: Vec<u8>,
        registrationfee: i64,
        version: u32,
    },
    NanoPay {
        sender: Vec<u8>,
        recipient: Vec<u8>,
        id: u64,
        amount: i64,
        txnexpiration: u64,
        nanopayexpiration: u64,
    },
    IssueAsset {
        sender: Vec<u8>,
        name: String,
        symbol: String,
        totalsupply: i64,
        precision: u32,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum PayloadType {
    Coinbase = 0,
    TransferAsset = 1,
    SigChain = 2,
    RegisterName = 3,
    TransferName = 4,
    DeleteName = 5,
    Subscribe = 6,
    Unsubscribe = 7,
    GenerateId = 8,
    NanoPay = 9,
    IssueAsset = 10,
    GenerateId2 = 11,
}

impl From<u32> for PayloadType {
    fn from(i: u32) -> Self {
        match i {
            0 => Self::Coinbase,
            1 => Self::TransferAsset,
            2 => Self::SigChain,
            3 => Self::RegisterName,
            4 => Self::TransferName,
            5 => Self::DeleteName,
            6 => Self::Subscribe,
            7 => Self::Unsubscribe,
            8 => Self::GenerateId,
            9 => Self::NanoPay,
            10 => Self::IssueAsset,
            11 => Self::GenerateId2,
            _ => unreachable!(),
        }
    }
}

impl ToString for PayloadType {
    fn to_string(&self) -> String {
        match self {
            PayloadType::Coinbase => "COINBASE_TYPE".into(),
            PayloadType::TransferAsset => "TRANSFER_ASSET_TYPE".into(),
            PayloadType::SigChain => "SIG_CHAIN_TXN_TYPE".into(),
            PayloadType::RegisterName => "REGISTER_NAME_TYPE".into(),
            PayloadType::TransferName => "TRANSFER_NAME_TYPE".into(),
            PayloadType::DeleteName => "DELETE_NAME_TYPE".into(),
            PayloadType::Subscribe => "SUBSCRIBE_TYPE".into(),
            PayloadType::Unsubscribe => "UNSUBSCRIBE_TYPE".into(),
            PayloadType::GenerateId => "GENERATE_ID_TYPE".into(),
            PayloadType::NanoPay => "NANO_PAY_TYPE".into(),
            PayloadType::IssueAsset => "ISSUE_ASSET_TYPE".into(),
            PayloadType::GenerateId2 => "GENERATE_ID_2_TYPE".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PayloadData {
    pub r#type: PayloadType,
    pub data: Vec<u8>,
}

pub fn pack_payload_data(payload: &Payload) -> PayloadData {
    let r#type = match payload {
        Payload::Coinbase { .. } => PayloadType::Coinbase,
        Payload::TransferAsset { .. } => PayloadType::TransferAsset,
        Payload::SigChain { .. } => PayloadType::SigChain,
        Payload::RegisterName { .. } => PayloadType::RegisterName,
        Payload::TransferName { .. } => PayloadType::TransferName,
        Payload::DeleteName { .. } => PayloadType::DeleteName,
        Payload::Subscribe { .. } => PayloadType::Subscribe,
        Payload::Unsubscribe { .. } => PayloadType::Unsubscribe,
        Payload::GenerateId { .. } => PayloadType::GenerateId,
        Payload::NanoPay { .. } => PayloadType::NanoPay,
        Payload::IssueAsset { .. } => PayloadType::IssueAsset,
    };
    let data = serde_json::to_vec(payload).unwrap();

    PayloadData { r#type, data }
}

pub fn unpack_payload_data(payload_data: &PayloadData) -> Payload {
    serde_json::from_slice(&payload_data.data).unwrap()
}

fn serialize_payload_data(payload_data: &PayloadData) -> Vec<u8> {
    let mut bytes = Vec::new();
    let type32 = payload_data.r#type.clone() as u32;
    bytes.extend_from_slice(&type32.to_ne_bytes());
    bytes.extend_from_slice(&payload_data.data);
    bytes
}

fn deserialize_payload_data(bytes: &[u8]) -> PayloadData {
    let typ = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
    let data = &bytes[4..];

    PayloadData {
        r#type: typ.into(),
        data: data.to_vec(),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnsignedTx {
    pub payload_data: PayloadData,
    pub nonce: u64,
    pub fee: i64,
    pub attributes: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProgramInfo {
    pub code: String,
    pub parameter: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TxnInfo {
    pub tx_type: String,
    pub payload_data: String,
    pub nonce: u64,
    pub fee: i64,
    pub attributes: String,
    pub programs: Vec<ProgramInfo>,
    pub hash: String,
}

fn random_attrs() -> [u8; TX_NONCE_LEN] {
    let mut rng = thread_rng();
    let mut attrs = [0; TX_NONCE_LEN];
    rng.fill(&mut attrs);
    attrs
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Transaction {
    pub unsigned_tx: UnsignedTx,
    programs: Vec<Program>,
    hash: Option<Vec<u8>>,
    size: u32,
    is_signature_verified: bool,
}

impl Transaction {
    pub fn new(payload_data: PayloadData, nonce: u64, fee: i64, attrs: [u8; TX_NONCE_LEN]) -> Self {
        let unsigned_tx = UnsignedTx {
            payload_data,
            nonce,
            fee,
            attributes: attrs.to_vec(),
        };

        Self {
            unsigned_tx,
            programs: Vec::new(),
            hash: None,
            size: 0,
            is_signature_verified: false,
        }
    }

    pub fn new_transfer_asset(
        sender: &[u8],
        recipient: &[u8],
        nonce: u64,
        amount: i64,
        fee: i64,
    ) -> Self {
        let payload = Payload::TransferAsset {
            sender: sender.to_vec(),
            recipient: recipient.to_vec(),
            amount,
        };
        let payload_data = pack_payload_data(&payload);

        Self::new(payload_data, nonce, fee, random_attrs())
    }

    pub fn new_sig_chain(sig_chain: &[u8], submitter: &[u8], nonce: u64) -> Self {
        let payload = Payload::SigChain {
            sigchain: sig_chain.to_vec(),
            submitter: submitter.to_vec(),
        };
        let payload_data = pack_payload_data(&payload);

        Self::new(payload_data, nonce, 0, random_attrs())
    }

    pub fn new_register_name(
        registrant: &[u8],
        name: &str,
        nonce: u64,
        reg_fee: i64,
        fee: i64,
    ) -> Self {
        let payload = Payload::RegisterName {
            registrant: registrant.to_vec(),
            name: name.into(),
            fee: reg_fee,
        };
        let payload_data = pack_payload_data(&payload);

        Self::new(payload_data, nonce, fee, random_attrs())
    }

    pub fn new_transfer_name(
        registrant: &[u8],
        to: &[u8],
        name: &str,
        nonce: u64,
        fee: i64,
    ) -> Self {
        let payload = Payload::TransferName {
            registrant: registrant.to_vec(),
            recipient: to.to_vec(),
            name: name.into(),
        };
        let payload_data = pack_payload_data(&payload);

        Self::new(payload_data, nonce, fee, random_attrs())
    }

    pub fn new_delete_name(registrant: &[u8], name: &str, nonce: u64, fee: i64) -> Self {
        let payload = Payload::DeleteName {
            registrant: registrant.to_vec(),
            name: name.into(),
        };
        let payload_data = pack_payload_data(&payload);

        Self::new(payload_data, nonce, fee, random_attrs())
    }

    pub fn new_subscribe(
        subscriber: &[u8],
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        nonce: u64,
        fee: i64,
    ) -> Self {
        let payload = Payload::Subscribe {
            subscriber: subscriber.to_vec(),
            identifier: identifier.into(),
            topic: topic.into(),
            duration,
            meta: meta.into(),
        };
        let payload_data = pack_payload_data(&payload);

        Self::new(payload_data, nonce, fee, random_attrs())
    }

    pub fn new_unsubscribe(
        subscriber: &[u8],
        identifier: &str,
        topic: &str,
        nonce: u64,
        fee: i64,
    ) -> Self {
        let payload = Payload::Unsubscribe {
            subscriber: subscriber.to_vec(),
            identifier: identifier.into(),
            topic: topic.into(),
        };
        let payload_data = pack_payload_data(&payload);

        Self::new(payload_data, nonce, fee, random_attrs())
    }

    pub fn new_generate_id(
        public_key: &[u8],
        sender: &[u8],
        reg_fee: i64,
        version: u32,
        nonce: u64,
        fee: i64,
        attributes: &[u8],
    ) -> Self {
        let payload = Payload::GenerateId {
            publickey: public_key.to_vec(),
            sender: sender.to_vec(),
            registrationfee: reg_fee,
            version,
        };
        let payload_data = pack_payload_data(&payload);

        Self::new(payload_data, nonce, fee, random_attrs())
    }

    pub fn new_nano_pay(
        sender: &[u8],
        recipient: &[u8],
        id: u64,
        amount: i64,
        txn_expiration: u64,
        nano_pay_expiration: u64,
    ) -> Self {
        let payload = Payload::NanoPay {
            sender: sender.to_vec(),
            recipient: recipient.to_vec(),
            id,
            amount,
            txnexpiration: txn_expiration,
            nanopayexpiration: nano_pay_expiration,
        };
        let payload_data = pack_payload_data(&payload);

        Self::new(payload_data, 0, 0, random_attrs())
    }

    pub fn new_issue_asset(
        sender: &[u8],
        name: &str,
        symbol: &str,
        total_supply: i64,
        precision: u32,
        nonce: u64,
        fee: i64,
    ) -> Self {
        let payload = Payload::IssueAsset {
            sender: sender.to_vec(),
            name: name.into(),
            symbol: symbol.into(),
            precision,
            totalsupply: total_supply,
        };
        let payload_data = pack_payload_data(&payload);

        Self::new(payload_data, nonce, fee, random_attrs())
    }

    pub fn size(&self) -> u32 {
        if self.size > 0 {
            self.size
        } else {
            serde_json::to_string(self).unwrap().as_bytes().len() as u32
        }
    }

    pub fn message(&self) -> Vec<u8> {
        get_hash_data(self)
    }

    pub fn hash(&self) -> Vec<u8> {
        match &self.hash {
            Some(hash) => hash.clone(),
            None => sha256_hash(&get_hash_data(self)),
        }
    }

    pub fn verify(&self, height: u64) -> Result<bool, String> {
        todo!()
    }

    pub fn verify_signature(&mut self) -> bool {
        if self.unsigned_tx.payload_data.r#type == PayloadType::Coinbase {
            return false;
        }

        if self.is_signature_verified {
            return false;
        }

        self.is_signature_verified = verify_signable_data(self);
        self.is_signature_verified
    }

    pub fn info(&self) -> TxnInfo {
        let mut programs = Vec::new();

        for program in &self.programs {
            programs.push(ProgramInfo {
                code: hex::encode(&program.code),
                parameter: hex::encode(&program.parameter),
            });
        }

        TxnInfo {
            tx_type: self.unsigned_tx.payload_data.r#type.to_string(),
            payload_data: hex::encode(&self.unsigned_tx.payload_data.data),
            nonce: self.unsigned_tx.nonce,
            fee: self.unsigned_tx.fee,
            attributes: hex::encode(&self.unsigned_tx.attributes),
            programs,
            hash: hex::encode(self.hash()),
        }
    }
}

impl SignableData for Transaction {
    fn program_hashes(&self) -> Vec<Vec<u8>> {
        let payload = unpack_payload_data(&self.unsigned_tx.payload_data);

        match payload {
            Payload::Coinbase { sender, .. } => vec![sender],
            Payload::TransferAsset { sender, .. } => vec![sender],
            Payload::SigChain { submitter, .. } => vec![submitter],
            Payload::RegisterName { registrant, .. } => vec![create_program_hash(&registrant)],
            Payload::TransferName { registrant, .. } => vec![create_program_hash(&registrant)],
            Payload::DeleteName { registrant, .. } => vec![create_program_hash(&registrant)],
            Payload::Subscribe { subscriber, .. } => vec![create_program_hash(&subscriber)],
            Payload::Unsubscribe { subscriber, .. } => vec![create_program_hash(&subscriber)],
            Payload::GenerateId {
                sender, publickey, ..
            } => {
                let program_hash = if !sender.is_empty() {
                    sender
                } else {
                    create_program_hash(&publickey)
                };

                vec![program_hash]
            }
            Payload::NanoPay { sender, .. } => vec![sender],
            Payload::IssueAsset { sender, .. } => vec![sender],
        }
    }

    fn programs(&self) -> &[Program] {
        &self.programs
    }

    fn set_programs(&mut self, programs: Vec<Program>) {
        self.programs = programs;
    }

    fn serialize_unsigned(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&serialize_payload_data(&self.unsigned_tx.payload_data));
        bytes.extend_from_slice(&self.unsigned_tx.nonce.to_ne_bytes());
        bytes.extend_from_slice(&self.unsigned_tx.fee.to_ne_bytes());
        bytes.extend_from_slice(&self.unsigned_tx.attributes);
        bytes
    }
}
