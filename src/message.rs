use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::sync::mpsc::Sender;

pub const MESSAGE_ID_SIZE: usize = 8;

pub type Reply = (String, MessagePayload, bool);

#[derive(Debug, Deserialize, Serialize)]
pub enum MessagePayloadType {
    Binary = 0,
    Text = 1,
    Ack = 2,
    Session = 3,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MessagePayload {
    pub r#type: MessagePayloadType,
    pub message_id: Vec<u8>,
    pub data: Vec<u8>,
    pub reply_to_id: Vec<u8>,
    pub no_reply: bool,
}

impl MessagePayload {
    pub fn new_binary(data: &[u8], message_id: &[u8], reply_to_id: &[u8], no_reply: bool) -> Self {
        let message_id = if message_id.is_empty() && reply_to_id.is_empty() {
            let mut rng = thread_rng();
            let mut message_id = [0; MESSAGE_ID_SIZE];
            rng.fill(&mut message_id);
            message_id.to_vec()
        } else {
            message_id.to_vec()
        };

        Self {
            r#type: MessagePayloadType::Binary,
            message_id,
            data: data.to_vec(),
            reply_to_id: reply_to_id.to_vec(),
            no_reply,
        }
    }

    pub fn new_text(text: &str, message_id: &[u8], reply_to_id: &[u8], no_reply: bool) -> Self {
        let message_id = if message_id.is_empty() && reply_to_id.is_empty() {
            let mut rng = thread_rng();
            let mut message_id = [0; MESSAGE_ID_SIZE];
            rng.fill(&mut message_id);
            message_id.to_vec()
        } else {
            message_id.to_vec()
        };

        Self {
            r#type: MessagePayloadType::Text,
            message_id,
            data: text.into(),
            reply_to_id: reply_to_id.to_vec(),
            no_reply,
        }
    }

    pub fn new_ack(reply_to_id: &[u8]) -> Self {
        Self {
            r#type: MessagePayloadType::Ack,
            message_id: Vec::new(),
            data: Vec::new(),
            reply_to_id: reply_to_id.to_vec(),
            no_reply: false,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayloadMessage {
    pub payload: Vec<u8>,
    pub encrypted: bool,
    pub nonce: Vec<u8>,
    pub encrypted_key: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TextData {
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct MessageConfig {
    pub unencrypted: bool,
    pub no_reply: bool,
    pub max_holding_seconds: u32,
    pub message_id: Vec<u8>,
    pub tx_pool: bool,
    pub offset: u32,
    pub limit: u32,
}

impl Default for MessageConfig {
    fn default() -> Self {
        Self {
            unencrypted: false,
            no_reply: false,
            max_holding_seconds: 0,
            message_id: Vec::new(),
            tx_pool: false,
            offset: 0,
            limit: 1000,
        }
    }
}

#[derive(Debug)]
pub struct Message {
    pub src: String,
    pub data: Vec<u8>,
    pub r#type: u32,
    pub encrypted: bool,
    pub message_id: Vec<u8>,
    pub no_reply: bool,
    pub reply_tx: Sender<(String, MessagePayload, bool)>,
}

impl Message {
    pub fn source(&self) -> &str {
        &self.src
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    fn reply(&self, payload: MessagePayload) -> Result<(), String> {
        if !self.no_reply {
            self.reply_tx
                .send((self.src.clone(), payload, self.encrypted))
                .unwrap();
        }
        Ok(())
    }

    pub fn reply_binary(&self, data: &[u8]) -> Result<(), String> {
        let payload = MessagePayload::new_binary(data, &[], &self.message_id, false);
        self.reply(payload)
    }

    pub fn reply_text(&self, text: &str) -> Result<(), String> {
        let payload = MessagePayload::new_text(text, &[], &self.message_id, false);
        self.reply(payload)
    }
}
