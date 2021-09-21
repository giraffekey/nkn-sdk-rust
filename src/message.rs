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

pub struct Message {}
