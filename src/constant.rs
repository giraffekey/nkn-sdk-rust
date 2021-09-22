pub const CHECKSIG: u8 = 0xAC;
// FOOLPROOFPREFIX used for fool-proof prefix
// base58.BitcoinEncoding[21] = 'N', base58.BitcoinEncoding[18] = 'K'
// 33 = len(base58.Encode( (2**192).Bytes() )),  192 = 8bit * (UINT160SIZE + SHA256CHKSUM)
// ((21 * 58**35) + (18 * 58**34) + (21 * 58**33)) >> 192 = 0x02b824
pub const FOOL_PROOF_PREFIX: u64 = 0x02b824 + 1; // +1 for avoid affected by lower 192bits shift-add
pub const SHA256_CHECKSUM: usize = 4;
pub const DEFAULT_RPC_TIMEOUT: u32 = 10000;
pub const DEFAULT_RPC_CONCURRENCY: u32 = 10000;
