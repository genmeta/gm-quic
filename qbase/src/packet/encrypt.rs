use std::ops::Deref;

use rustls::quic::{HeaderProtectionKey, PacketKey};

use super::{KeyPhaseBit, LongClearBits, ShortClearBits};

/// 有一个Packet了
/// 1. 先填写完整 complete PacketNumber ClearBits
/// 2. 有了头部之后，加密body
/// 3. 添加头部保护

pub fn encrypt_packet(key: &dyn PacketKey, pn: u64, pkt_buf: &mut [u8], body_offset: usize) {
    let (aad, body) = pkt_buf.split_at_mut(body_offset);
    key.encrypt_in_place(pn, aad, body).unwrap();
}

pub fn protect_long_header(
    key: &dyn HeaderProtectionKey,
    pkt_buf: &mut [u8],
    pn_len: usize,
    payload_offset: usize,
) {
    let (predata, payload) = pkt_buf.split_at_mut(payload_offset);
    let first_byte = &mut predata[0];

    let clear_bits = LongClearBits::with_pn_len(pn_len);
    *first_byte |= clear_bits.deref();

    let (max_pn_buf, sample) = payload.split_at_mut(4);
    let sample_len = key.sample_len();
    key.encrypt_in_place(&sample[..sample_len], first_byte, &mut max_pn_buf[..pn_len])
        .unwrap();
}

pub fn protect_short_header(
    key: &dyn HeaderProtectionKey,
    pkt_buf: &mut [u8],
    pn_len: usize,
    key_phase: KeyPhaseBit,
    payload_offset: usize,
) {
    let (predata, payload) = pkt_buf.split_at_mut(payload_offset);
    let first_byte = &mut predata[0];

    let mut clear_bits = ShortClearBits::with_pn_len(pn_len);
    clear_bits.set_key_phase(key_phase);
    *first_byte |= clear_bits.deref();

    let (max_pn_buf, sample) = payload.split_at_mut(4);
    let sample_len = key.sample_len();
    key.encrypt_in_place(&sample[..sample_len], first_byte, &mut max_pn_buf[..pn_len])
        .unwrap();
}

#[cfg(test)]
mod tests {}
