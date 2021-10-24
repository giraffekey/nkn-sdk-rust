use crate::serialization::{write_bool, write_u32, write_var_bytes};

#[derive(Debug)]
pub enum SigAlgo {
    Signature = 0,
    Hash = 1,
}

#[derive(Debug)]
pub struct SigChainElement {
    pub id: Vec<u8>,
    pub next_pubkey: Vec<u8>,
    pub mining: bool,
    pub signature: Vec<u8>,
    pub sig_algo: SigAlgo,
    pub vrf: Vec<u8>,
    pub proof: Vec<u8>,
}

impl SigChainElement {
    pub fn serialize_unsigned(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_var_bytes(&mut bytes, &self.id);
        write_var_bytes(&mut bytes, &self.next_pubkey);
        write_bool(&mut bytes, self.mining);
        bytes.extend_from_slice(&self.vrf);
        bytes
    }
}

#[derive(Debug)]
pub struct SigChain {
    pub nonce: u32,
    pub data_size: u32,
    pub block_hash: Vec<u8>,
    pub src_id: Vec<u8>,
    pub src_pubkey: Vec<u8>,
    pub dest_id: Vec<u8>,
    pub dest_pubkey: Vec<u8>,
    pub elems: Vec<SigChainElement>,
}

impl SigChain {
    pub fn serialize_metadata(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_u32(&mut bytes, self.nonce);
        write_u32(&mut bytes, self.data_size);
        write_var_bytes(&mut bytes, &self.block_hash);
        write_var_bytes(&mut bytes, &self.src_id);
        write_var_bytes(&mut bytes, &self.src_pubkey);
        write_var_bytes(&mut bytes, &self.dest_id);
        write_var_bytes(&mut bytes, &self.dest_pubkey);
        bytes
    }
}
