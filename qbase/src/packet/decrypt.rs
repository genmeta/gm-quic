use rustls::quic::{HeaderProtectionKey, PacketKey};

use super::{
    error::Error, take_pn_len, GetPacketNumberLength, KeyPhaseBit, LongSpecificBits, PacketNumber,
    ShortSpecificBits,
};

/// Removes the header protection of the long packet.
/// Returns the undecoded packet number in the header finally.
///
/// When receiving a long packet, the header protection must be removed before
/// the packet number can be decoded. If removing header protection is failed, it
/// indicates that the packet is problematic and can be ignored.
/// In this case, no error but None will be returned.
/// If not so, it will put the QUIC connection in a situation that is highly susceptible
/// to denial-of-service attacks.
///
/// Note that after removing the long header protection, the 2-bit reserved bits of the
/// long header, i.e., the 5th and 6th bits of the first byte of the first byte, must
/// be 0, otherwise it will return a connection error of type PROTOCOL_VIOLATION.
///
/// See [Section 17.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.2) of
/// QUIC RFC 9000.
///
/// After obtaining the undecoded packet number, it is necessary to rely on the largest
/// received packet number to further decode the actual packet number.
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
        .decrypt_in_place(&sample[..key.sample_len()], first_byte, max_pn_buf)
        .is_err()
    {
        return Ok(None);
    }

    let specific_bits = LongSpecificBits::from(*first_byte);
    let pn_len = specific_bits.pn_len()?;
    let (_, undecoded_pn) = take_pn_len(pn_len)(max_pn_buf).unwrap();

    Ok(Some(undecoded_pn))
}

/// Removes the header protection of the short packet.
/// Returns the undecoded packet number and the key phase bit in the header.
///
/// When receiving a short packet, the header protection must be removed first before
/// the packet number can be decoded. If removing header protection is failed, it
/// indicates that the packet is problematic and can be ignored.
/// In this case, no error but None will be returned instead.
/// If not so, it will put the QUIC connection in a situation that is highly susceptible
/// to denial-of-service attacks.
///
/// Note that after removing the long header protection, the 2-bit reserved bits of the
/// long header, i.e., the 4th and 5th bits of the first byte of the first byte, must
/// be 0, otherwise it will return a connection error of type PROTOCOL_VIOLATION.
///
/// See [Section 17.3.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1-4.8) of
/// QUIC RFC 9000.
///
/// After obtaining the undecoded packet number, it is necessary to rely on the maximum
/// receiving packet number to further decode the actual packet number.
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
        .decrypt_in_place(&sample[..key.sample_len()], first_byte, max_pn_buf)
        .is_err()
    {
        return Ok(None);
    }

    let clear_bits = ShortSpecificBits::from(*first_byte);
    let pn_len = clear_bits.pn_len()?;
    let (_, undecoded_pn) = take_pn_len(pn_len)(max_pn_buf).unwrap();

    Ok(Some((undecoded_pn, clear_bits.key_phase())))
}

/// Decrypt the body of a packet, applicable to both long and short packets.
///
/// It will decrypt the body data of the packet in place and return the length of the valid
/// plaintext body data in the packet.
/// The final valid plaintext body length is not equal to the raw ciphered body length of the packet.
/// This is because the ciphertext body length usually contains checksum codes at the end,
/// which is not part of the plaintext body.
///
/// Decrypting a packet relies on the packet number decoded from the packet header, and then
/// uses the corresponding level of packet decryption key to decrypt the packet body.
/// The packet body refers to the content located after the packet number.
/// Decrypting a packet will verify the integrity of the packet.
/// If decryption fails, it indicates that the packet is incorrect (strangely, removing the
/// header protection succeeded, right?), indicating an error in the peer's packaging
/// and encrypting logic, and then the QUIC connection should be terminated.
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
