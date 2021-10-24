use bytes::{BufMut, BytesMut};

pub fn write_var_u64(bytes: &mut Vec<u8>, val: u64) {
    let mut buf = BytesMut::with_capacity(9);

    if val < 0xFD {
        buf.put_u8(val as u8);
        buf.truncate(1);
    } else if val <= 0xFFFF {
        buf.put_u8(0xFD);
        buf.put_u16(val as u16);
        buf.truncate(3);
    } else if val <= 0xFFFFFFFF {
        buf.put_u8(0xFE);
        buf.put_u32(val as u32);
        buf.truncate(5);
    } else {
        buf.put_u8(0xFF);
        buf.put_u64(val);
    }

    bytes.extend_from_slice(&buf);
}

pub fn read_var_u64(bytes: &mut Vec<u8>) -> u64 {
    todo!()
}

pub fn write_var_bytes(bytes: &mut Vec<u8>, val: &[u8]) {
    write_var_u64(bytes, val.len() as u64);
    bytes.extend_from_slice(val);
}

pub fn read_var_bytes(bytes: &mut Vec<u8>) -> Vec<u8> {
    todo!()
}

pub fn write_var_str(bytes: &mut Vec<u8>, val: &str) {
    todo!()
}

pub fn read_var_str(bytes: &mut Vec<u8>) -> String {
    todo!()
}

pub fn write_u8(bytes: &mut Vec<u8>, val: u8) {
    todo!()
}

pub fn read_u8(bytes: &mut Vec<u8>) -> u8 {
    todo!()
}

pub fn write_u16(bytes: &mut Vec<u8>, val: u16) {
    todo!()
}

pub fn read_u16(bytes: &mut Vec<u8>) -> u16 {
    todo!()
}

pub fn write_u32(bytes: &mut Vec<u8>, val: u32) {
    todo!()
}

pub fn read_u32(bytes: &mut Vec<u8>) -> u32 {
    todo!()
}

pub fn write_u64(bytes: &mut Vec<u8>, val: u64) {
    todo!()
}

pub fn read_u64(bytes: &mut Vec<u8>) -> u64 {
    todo!()
}

pub fn write_bool(bytes: &mut Vec<u8>, val: bool) {
    todo!()
}

pub fn read_bool(bytes: &mut Vec<u8>) -> bool {
    todo!()
}
