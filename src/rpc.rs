pub struct Node {
    address: String,
    rpc_address: String,
    public_key: Vec<u8>,
    identifier: String,
}

pub struct Registrant {
    registrant: String,
    expires_at: u64,
}

pub struct Subscription {
    meta: String,
    expires_at: u64,
}
