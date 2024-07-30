pub mod receive;

use std::{fmt::Debug, ops::Deref};

use bytes::BufMut;
use qbase::{
    cid::ConnectionId,
    packet::{
        header::{Encode, GetType, LongHeader, Write, WriteLongHeader, WriteOneRttHeader},
        keys::{AllKeys, ArcKeys, ArcOneRttKeys},
        Header, LongClearBits, LongHeaderBuilder, OneRttHeader, ShortClearBits, SpinBit,
    },
    varint::{VarInt, WriteVarInt},
};
use qrecovery::space::Epoch;

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

pub fn encrypt_long_header_space<T>(
    buffer: &mut [u8],
    header: &LongHeader<T>,
    pn: u64,
    pn_size: usize,
    mut body_len: usize,
    fill_policy: FillPolicy,
    keys: &ArcKeys,
) -> (usize, usize)
where
    for<'a> &'a mut [u8]: Write<T>,
    LongHeader<T>: GetType + Encode,
{
    let keys = match keys.get_local_keys() {
        Some(keys) => keys,
        None => return (0, 0),
    };

    // 放到 path 装填时
    let max_header_size = header.size() + 2; // 2 bytes reserved for packet length, max 16KB
    let (mut hdr_buf, body_buf) = buffer.split_at_mut(max_header_size);

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

    (offset, pkt_size)
}

pub fn encrypt_1rtt_space(
    buffer: &mut [u8],
    header: &OneRttHeader,
    keys: ArcOneRttKeys,
    pn: u64,
    pn_size: usize,
    body_len: usize,
) -> usize {
    let (hpk, pk) = match keys.get_local_keys() {
        Some(keys) => keys,
        None => return 0,
    };

    let header_size = header.size();

    let (mut hdr_buf, _) = buffer.split_at_mut(header_size);

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

    pkt_size
}

pub fn build_header(
    epoch: Epoch,
    scid: ConnectionId,
    dcid: ConnectionId,
    spin: SpinBit,
    token: Vec<u8>,
) -> (Header, usize) {
    match epoch {
        Epoch::Initial => {
            let inital_hdr = LongHeaderBuilder::with_cid(dcid, scid).initial(token.clone());
            let size = inital_hdr.size() + 2; // 2 bytes reserved for packet length, max 16KB
            (Header::Initial(inital_hdr), size)
        }
        Epoch::Handshake => {
            let handshake_hdr = LongHeaderBuilder::with_cid(dcid, scid).handshake();
            let size = handshake_hdr.size() + 2;
            (Header::Handshake(handshake_hdr), size)
        }
        Epoch::Data => {
            // todo: 可能有 0 RTT 数据要发送
            // 如果 data space 有数据，但是没有 1 rtt 密钥, 有 0 rtt 密钥
            let data_hdr = OneRttHeader { spin, dcid };
            let size = data_hdr.size() + 2;
            (Header::OneRtt(data_hdr), size)
        }
    }
}

pub fn encrypt_packet(
    buf: &mut [u8],
    header: &Header,
    pn: u64,
    pn_size: usize,
    body_len: usize,
    keys: &AllKeys,
) -> usize {
    match header {
        Header::Initial(header) => {
            let fill_policy = FillPolicy::Redundancy;
            let (_, sent_bytes) = encrypt_long_header_space(
                buf,
                header,
                pn,
                pn_size,
                body_len,
                fill_policy,
                &keys.initial_keys.clone().unwrap(),
            );
            sent_bytes
        }
        Header::Handshake(header) => {
            let fill_policy = FillPolicy::Redundancy;
            let (_, sent_bytes) = encrypt_long_header_space(
                buf,
                header,
                pn,
                pn_size,
                body_len,
                fill_policy,
                &keys.handshake_keys.clone().unwrap(),
            );
            sent_bytes
        }
        Header::OneRtt(header) => encrypt_1rtt_space(
            buf,
            header,
            keys.one_rtt_keys.clone().unwrap(),
            pn,
            pn_size,
            body_len,
        ),
        _ => {
            todo!("send 0rtt retry VN packet");
        }
    }
}
#[cfg(test)]
mod tests {}
