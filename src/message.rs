use rand::{thread_rng, Rng};

pub const MESSAGE_ID_SIZE: usize = 8;

#[derive(Debug)]
pub enum MessagePayloadType {
    Binary = 0,
    Text = 1,
    Ack = 2,
    Session = 3,
}

#[derive(Debug)]
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

#[derive(Debug)]
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
    source: String,
    data: Vec<u8>,
    type_: u32,
    encrypted: bool,
    message_id: Vec<u8>,
    no_reply: bool,
}

impl Message {
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn reply(&self, data: impl Into<Vec<u8>>) {
        todo!()
    }

    pub fn reply_binary(&self, data: &[u8]) {
        self.reply(data)
    }

    pub fn reply_text(&self, data: &str) {
        self.reply(data)
    }
}
