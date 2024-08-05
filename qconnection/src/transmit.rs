use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use bytes::BufMut;
use qbase::{
    packet::{
        header::{Encode, GetType, LongHeader, Write, WriteLongHeader, WriteOneRttHeader},
        keys::OneRttPacketKeys,
        LongClearBits, OneRttHeader, ShortClearBits,
    },
    varint::{VarInt, WriteVarInt},
};
use rustls::quic::HeaderProtectionKey;

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

pub fn read_long_header_and_encrypt<T>(
    buffer: &mut [u8],
    header: &LongHeader<T>,
    pn: u64,
    pn_size: usize,
    body_size: usize,
    keys: &rustls::quic::Keys,
    fill_policy: FillPolicy,
) -> usize
where
    for<'a> &'a mut [u8]: Write<T>,
    LongHeader<T>: GetType + Encode,
{
    let max_header_size = header.size() + 2; // 2 bytes reserved for packet length, max 16KB
    let (mut hdr_buf, _) = buffer.split_at_mut(max_header_size);

    let mut offset = 0;
    if body_size < 0x40 {
        match fill_policy {
            FillPolicy::Misalignment => {
                // Misalignment padding: If it is less than 64 bytes, ignore the first byte and start
                // padding the header from the second byte. Do the same when sending packets.
                offset = 1;
                hdr_buf = &mut hdr_buf[1..];
                hdr_buf.put_long_header(header);
                hdr_buf.put_varint(&VarInt::from_u64(body_size as u64).unwrap());
            }
            FillPolicy::Redundancy => {
                // Redundant encoding VarInt: If it is less than 64 bytes, use 2 bytes to encode the
                // length. The first byte is 0x40, meaning VarInt is 2 bytes long, and the second byte is the actual length.
                hdr_buf.put_long_header(header);
                hdr_buf.put_u8(0x40);
                hdr_buf.put_u8(body_size as u8);
            }
        }
    } else {
        hdr_buf.put_long_header(header);
        hdr_buf.put_varint(&VarInt::from_u64(body_size as u64).unwrap());
    }

    let payload_offset = max_header_size - offset;
    let body_offset = payload_offset + pn_size;
    let pkt_size = body_offset + body_size;
    let pkt_buffer = &mut buffer[offset..offset + pkt_size];
    // encode pn length in the first byte
    let clear_bits = LongClearBits::with_pn_len(pn_size);
    pkt_buffer[0] |= clear_bits.deref();

    // encrypt packet payload
    let (header, body) = pkt_buffer.split_at_mut(body_offset);
    keys.deref()
        .local
        .packet
        .encrypt_in_place(pn, header, body)
        .unwrap();

    // add header protection
    let (header, pn_and_body) = pkt_buffer.split_at_mut(payload_offset);
    let (pn_max, sample) = pn_and_body.split_at_mut(4);
    keys.deref()
        .local
        .header
        .encrypt_in_place(sample, &mut header[0], &mut pn_max[..pn_size])
        .unwrap();

    pkt_size
}

pub fn read_short_header_and_encrypt(
    mut buffer: &mut [u8],
    header: &OneRttHeader,
    pn: u64,
    pn_size: usize,
    body_size: usize,
    (hpk, pk): &(Arc<dyn HeaderProtectionKey>, Arc<Mutex<OneRttPacketKeys>>),
) -> usize {
    let header_size = header.size();

    buffer.put_one_rtt_header(header);

    let body_offset = header_size + pn_size;
    let pkt_size = header_size + body_size;
    let pkt_buffer = &mut buffer[0..pkt_size];

    // encode pn length in the first byte
    let (key_phase, pk) = pk.lock().unwrap().get_local();
    let mut clear_bits = ShortClearBits::with_pn_len(pn_size);
    clear_bits.set_key_phase(key_phase);
    pkt_buffer[0] |= *clear_bits;

    // encrypt packet payload
    let (header, body) = pkt_buffer.split_at_mut(body_offset);
    pk.deref().encrypt_in_place(pn, header, body).unwrap();

    // add header protection
    let (header, payload) = pkt_buffer.split_at_mut(header_size);
    let (pn_max, sample) = payload.split_at_mut(4);
    hpk.deref()
        .encrypt_in_place(sample, &mut header[0], &mut pn_max[..pn_size])
        .unwrap();

    pkt_size
}
