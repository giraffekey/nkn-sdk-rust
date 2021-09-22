use crate::RPCConfig;

use std::collections::HashMap;

pub struct Subscribers {
    map: HashMap<String, String>,
    tx_pool_map: HashMap<String, String>,
}

impl Subscribers {
    fn map(&self) -> &HashMap<String, String> {
        &self.map
    }

    fn tx_pool_map(&self) -> &HashMap<String, String> {
        &self.tx_pool_map
    }
}

pub fn get_subscribers(
    topic: &str,
    offset: u32,
    limit: u32,
    meta: bool,
    tx_pool: bool,
    config: RPCConfig,
) -> Subscribers {
    todo!()
}
