use rustls::quic::{HeaderProtectionKey, PacketKey};

use super::{
    error::Error, take_pn_len, GetPacketNumberLength, KeyPhaseBit, LongClearBits, PacketNumber,
    ShortClearBits,
};

pub fn remove_protection_of_long_packet(
    key: &dyn HeaderProtectionKey,
    pkt_buf: &mut [u8],
    payload_offset: usize,
) -> Result<Option<PacketNumber>, Error> {
    let (pre_data, payload) = pkt_buf.split_at_mut(payload_offset);
    let first_byte = &mut pre_data[0];
    let (max_pn_buf, sample) = payload.split_at_mut(4);
    // 去除包头保护失败，忽略即可
    if key
        .decrypt_in_place(sample, first_byte, max_pn_buf)
        .is_err()
    {
        return Ok(None);
    }

    let clear_bits = LongClearBits::from(*first_byte);
    let pn_len = clear_bits.pn_len()?;
    let (_, undecoded_pn) = take_pn_len(pn_len)(max_pn_buf).unwrap();

    Ok(Some(undecoded_pn))
}

pub fn remove_protection_of_short_packet(
    key: &dyn HeaderProtectionKey,
    pkt_buf: &mut [u8],
    payload_offset: usize,
) -> Result<Option<(PacketNumber, KeyPhaseBit)>, Error> {
    let (pre_data, payload) = pkt_buf.split_at_mut(payload_offset);
    let first_byte = &mut pre_data[0];
    let (max_pn_buf, sample) = payload.split_at_mut(4);
    // 去除包头保护失败，忽略即可
    if key
        .decrypt_in_place(sample, first_byte, max_pn_buf)
        .is_err()
    {
        return Ok(None);
    }

    let clear_bits = ShortClearBits::from(*first_byte);
    let pn_len = clear_bits.pn_len()?;
    let (_, undecoded_pn) = take_pn_len(pn_len)(max_pn_buf).unwrap();

    Ok(Some((undecoded_pn, clear_bits.key_phase())))
}

pub fn decrypt_packet(
    key: &dyn PacketKey,
    pn: u64,
    pkt_buf: &mut [u8],
    body_offset: usize,
) -> Result<usize, Error> {
    let (aad, body) = pkt_buf.split_at_mut(body_offset);
    let plain = key
        .decrypt_in_place(pn, aad, body)
        .map_err(|_| Error::DecryptPacketFailure)?;
    // should return plain.len()
    Ok(plain.len())
}
