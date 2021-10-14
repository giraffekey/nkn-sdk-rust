use crate::crypto::sha256_hash;
use crate::program::Program;
use crate::signature::SignableData;
use crate::signature::{get_hash_data, verify_signable_data};

use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

const TX_NONCE_LEN: usize = 32;

#[derive(Debug)]
pub struct TransactionConfig {
    pub fee: u64,
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
enum Payload {
    Coinbase {
        sender: Vec<u8>,
        recipient: Vec<u8>,
        amount: u64,
    },
    TransferAsset {
        sender: Vec<u8>,
        recipient: Vec<u8>,
        amount: u64,
    },
    SigChain {
        sigchain: Vec<u8>,
        submitter: Vec<u8>,
    },
    RegisterName {
        registrant: Vec<u8>,
        name: String,
        fee: u64,
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
        public_key: Vec<u8>,
        sender: Vec<u8>,
        registrationfee: u64,
        version: u32,
    },
    NanoPay {
        sender: Vec<u8>,
        recipient: Vec<u8>,
        id: u64,
        amount: u64,
        txn_expiration: u32,
        nano_pay_expiration: u32,
    },
    IssueAsset {
        sender: Vec<u8>,
        name: String,
        symbol: String,
        total_supply: u64,
        precision: u32,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
enum PayloadType {
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

#[derive(Debug, Deserialize, Serialize)]
pub struct PayloadData {
    r#type: PayloadType,
    data: Vec<u8>,
}

fn pack_payload_data(payload: &Payload) -> PayloadData {
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

    PayloadData {
        r#type,
        data,
    }
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

#[derive(Debug, Deserialize, Serialize)]
pub struct UnsignedTx {
    pub payload_data: PayloadData,
    pub nonce: u64,
    pub fee: u64,
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
    pub fee: u64,
    pub attributes: String,
    pub programs: Vec<ProgramInfo>,
    pub hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Transaction {
    pub unsigned_tx: UnsignedTx,
    programs: Vec<Program>,
    hash: Option<Vec<u8>>,
    size: u32,
    is_signature_verified: bool,
}

impl Transaction {
    pub fn new(payload_data: PayloadData, nonce: u64, fee: u64, attrs: &[u8]) -> Self {
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
        amount: u64,
        fee: u64,
    ) -> Self {
        let payload = Payload::TransferAsset {
            sender: sender.to_vec(),
            recipient: recipient.to_vec(),
            amount,
        };
        let payload_data = pack_payload_data(&payload);

        let mut rng = thread_rng();
        let mut attrs = [0u8; TX_NONCE_LEN];
        rng.fill(&mut attrs);

        Self::new(payload_data, nonce, fee, &attrs)
    }

    pub fn new_sig_chain(sig_chain: &[u8], submitter: &[u8], nonce: u64) -> Self {
        todo!()
    }

    pub fn new_register_name(
        registrant: &[u8],
        name: &str,
        nonce: u64,
        reg_fee: u64,
        fee: u64,
    ) -> Self {
        todo!()
    }

    pub fn new_transfer_name(
        registrant: &[u8],
        to: &[u8],
        name: &str,
        nonce: u64,
        fee: u64,
    ) -> Self {
        todo!()
    }

    pub fn new_delete_name(registrant: &[u8], name: &str, nonce: u64, fee: u64) -> Self {
        todo!()
    }

    pub fn new_subscribe(
        subscriber: &[u8],
        identifier: &str,
        topic: &str,
        duration: u32,
        meta: &str,
        nonce: u64,
        fee: u64,
    ) -> Self {
        todo!()
    }

    pub fn new_unsubscribe(
        subscriber: &[u8],
        identifier: &str,
        topic: &str,
        nonce: u64,
        fee: u64,
    ) -> Self {
        todo!()
    }

    pub fn new_generate_id(
        public_key: &[u8],
        sender: &[u8],
        reg_fee: u64,
        version: u32,
        nonce: u64,
        fee: u64,
        attributes: &[u8],
    ) -> Self {
        todo!()
    }

    pub fn new_nano_pay(
        sender: &[u8],
        recipient: &[u8],
        id: u64,
        amount: u64,
        txn_expiration: u32,
        nano_pay_expiration: u32,
    ) -> Self {
        todo!()
    }

    pub fn new_issue_asset(
        sender: &[u8],
        name: &str,
        symbol: &str,
        total_supply: u64,
        precision: u32,
        nonce: u64,
        fee: u64,
    ) -> Self {
        todo!()
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

    pub fn get_info(&self) -> TxnInfo {
        todo!()
    }
}

impl SignableData for Transaction {
    fn program_hashes(&self) -> Vec<Vec<u8>> {
        todo!()
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
