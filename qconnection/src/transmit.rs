pub mod receive;

use std::{fmt::Debug, ops::Deref, time::Instant};

use bytes::BufMut;
use qbase::{
    packet::{
        header::{Encode, GetType, LongHeader, Write, WriteLongHeader, WriteOneRttHeader},
        keys::{ArcKeys, ArcOneRttKeys},
        LongClearBits, OneRttHeader, ShortClearBits,
    },
    util::TransportLimit,
    varint::{VarInt, WriteVarInt},
};
use qcongestion::congestion::MSS;
use qrecovery::space::ReliableTransmit;

/// In order to fill the packet efficiently and reduce unnecessary copying, the data of each
/// space is directly written on the Buffer. However, the length of the packet header is
/// variable-length encoding, so space needs to be reserved.
/// However, when the length is too small (less than 64), the length only occupies 1 byte,
/// and the reserved space will have an extra byte. Either misalignment padding or redundant
/// variable-length encoding is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillPolicy {
    Misalignment,
    Redundancy,
    // Padding,     // Instead of padding frames, it's better to redundantly encode the Length.
}

pub fn read_space_and_encrypt<T>(
    buffer: &mut [u8],
    header: &LongHeader<T>,
    fill_policy: FillPolicy,
    keys: ArcKeys,
    space: &impl ReliableTransmit,
    transport_limit: &mut TransportLimit,
    ack_pkt: Option<(u64, Instant)>,
) -> (u64, usize, usize, bool)
where
    for<'a> &'a mut [u8]: Write<T>,
    LongHeader<T>: GetType + Encode,
{
    let keys = match keys.get_local_keys() {
        Some(keys) => keys,
        None => return (0, 0, 0, false),
    };

    let max_header_size = header.size() + 2; // 2 bytes reserved for packet length, max 16KB
    let (mut hdr_buf, body_buf) = buffer.split_at_mut(max_header_size);

    let (pn, pn_size, mut body_len, is_ack_eliciting) =
        space.read(transport_limit, body_buf, ack_pkt);
    if body_len == 0 {
        // nothing to send
        return (0, 0, 0, false);
    }

    let mut body_buf = &mut body_buf[body_len..];
    if body_len < 20 {
        // The sample requires at least 16 bytes, so the length must be at least 20 bytes.
        // If it is not enough, Padding(0x0) needs to be added.
        body_buf.put_bytes(0x0, 20 - body_len);
        body_len = 20;
    }

    let mut offset = 0;
    if body_len < 0x40 {
        match fill_policy {
            FillPolicy::Misalignment => {
                // Misalignment padding: If it is less than 64 bytes, ignore the first byte and start
                // padding the header from the second byte. Do the same when sending packets.
                offset = 1;
                hdr_buf = &mut hdr_buf[1..];
                hdr_buf.put_long_header(header);
                hdr_buf.put_varint(&VarInt::from_u64(body_len as u64).unwrap());
            }
            FillPolicy::Redundancy => {
                // Redundant encoding VarInt: If it is less than 64 bytes, use 2 bytes to encode the
                // length. The first byte is 0x40, meaning VarInt is 2 bytes long, and the second byte is the actual length.
                hdr_buf.put_long_header(header);
                hdr_buf.put_u8(0x40);
                hdr_buf.put_u8(body_len as u8);
            }
        }
    } else {
        hdr_buf.put_long_header(header);
        hdr_buf.put_varint(&VarInt::from_u64(body_len as u64).unwrap());
    }
    debug_assert!(hdr_buf.is_empty());

    let header_size = max_header_size - offset;
    let header_and_pn_size = header_size + pn_size;
    let pkt_size = header_size + body_len;
    let pkt_buffer = &mut buffer[offset..offset + pkt_size];
    // encode pn length in the first byte
    let clear_bits = LongClearBits::with_pn_size(pn_size);
    pkt_buffer[0] |= clear_bits.deref();

    // encrypt packet payload
    let (header, body) = pkt_buffer.split_at_mut(header_and_pn_size);
    keys.deref()
        .local
        .packet
        .encrypt_in_place(pn, header, body)
        .unwrap();

    // add header protection
    let (header, pn_and_body) = pkt_buffer.split_at_mut(header_size);
    let (pn_max, sample) = pn_and_body.split_at_mut(4);
    keys.deref()
        .local
        .header
        .encrypt_in_place(sample, &mut header[0], &mut pn_max[..pn_size])
        .unwrap();

    (pn, offset, pkt_size, is_ack_eliciting)
}

pub fn read_1rtt_data_and_encrypt(
    buffer: &mut [u8],
    header: &OneRttHeader,
    keys: ArcOneRttKeys,
    space: &impl ReliableTransmit,
    transport_limit: &mut TransportLimit,
    ack_pkt: Option<(u64, Instant)>,
) -> (u64, usize, bool) {
    let (hpk, pk) = match keys.get_local_keys() {
        Some(keys) => keys,
        None => return (0, 0, false),
    };

    let header_size = header.size();
    let (mut hdr_buf, body_buf) = buffer.split_at_mut(header_size);

    let (pn, pn_size, body_len, is_ack_eliciting) = space.read(transport_limit, body_buf, ack_pkt);
    if body_len == 0 {
        return (0, 0, false);
    }

    hdr_buf.put_one_rtt_header(header);
    debug_assert!(hdr_buf.is_empty());

    let header_and_pn_size = header_size + pn_size;
    let pkt_size = header_size + body_len;
    let pkt_buffer = &mut buffer[0..pkt_size];
    // encode pn length in the first byte
    let (key_phase, pk) = pk.lock().unwrap().get_local();
    let mut clear_bits = ShortClearBits::with_pn_size(pn_size);
    clear_bits.set_key_phase(key_phase);
    pkt_buffer[0] |= *clear_bits;

    // encrypt packet payload
    let (header, body) = pkt_buffer.split_at_mut(header_and_pn_size);
    pk.deref().encrypt_in_place(pn, header, body).unwrap();

    // add header protection
    let (header, pn_and_body) = pkt_buffer.split_at_mut(header_size);
    let (pn_max, sample) = pn_and_body.split_at_mut(4);
    hpk.deref()
        .encrypt_in_place(sample, &mut header[0], &mut pn_max[..pn_size])
        .unwrap();

    (pn, pkt_size, is_ack_eliciting)
}
pub fn read_long_header_space<T>(
    buffers: &mut Vec<Vec<u8>>,
    header: &LongHeader<T>,
    fill_policy: FillPolicy,
    keys: ArcKeys,
    space: &impl ReliableTransmit,
    limit: &mut TransportLimit,
    ack_pkt: Option<(u64, Instant)>,
) where
    for<'a> &'a mut [u8]: Write<T>,
    LongHeader<T>: GetType + Encode,
{
    let mut buffer = vec![0u8; MSS];
    let mut offset = 0;
    while limit.available() > 0 {
        let (_, pkt_size) = read_space_and_encrypt(
            &mut buffer[offset..],
            header,
            fill_policy,
            keys.clone(),
            space,
            limit,
            ack_pkt,
        );
        if pkt_size == 0 && offset == 0 {
            break;
        }
        if offset < MSS && pkt_size != 0 {
            offset += pkt_size;
        } else {
            buffers.push(buffer);
            buffer = vec![0u8; MSS];
            offset = 0;
        }
    }
}

pub fn read_short_header_space(
    buffers: &mut Vec<Vec<u8>>,
    header: OneRttHeader,
    keys: ArcOneRttKeys,
    space: &impl ReliableTransmit,
    limit: &mut TransportLimit,
    ack_pkt: Option<(u64, Instant)>,
) {
    let mut buffer = vec![0u8; MSS];
    let mut offset = 0;
    while limit.available() > 0 {
        let pkt_size = read_1rtt_data_and_encrypt(
            &mut buffer[offset..],
            &header,
            keys.clone(),
            space,
            limit,
            ack_pkt,
        );
        if pkt_size == 0 && offset == 0 {
            break;
        }
        if offset < MSS && pkt_size != 0 {
            offset += pkt_size;
        } else {
            buffers.push(buffer);
            buffer = vec![0u8; MSS];
            offset = 0;
        }
    }
}

#[cfg(test)]
mod tests {}
