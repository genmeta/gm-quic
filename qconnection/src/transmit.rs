use bytes::BufMut;
use qbase::{
    packet::{
        header::{
            Encode, GetType, HasLength, LongHeader, Write, WriteLongHeader, WriteOneRttHeader,
        },
        keys::{ArcKeys, ArcOneRttKeys},
        LongClearBits, OneRttHeader, ShortClearBits, WritePacketNumber,
    },
    varint::{VarInt, WriteVarInt},
};
use qrecovery::{
    space::{ArcSpace, TransmitPacket},
    streams::{ArcOutput, ReceiveStream, Streams, TransmitStream},
};
use std::ops::Deref;

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

pub fn read_space_and_encrypt<S, TX, RX>(
    buffer: &mut [u8],
    header: LongHeader<S>,
    fill_policy: FillPolicy,
    keys: ArcKeys,
    space: ArcSpace<TX, RX>,
) -> (usize, usize)
where
    for<'a> &'a mut [u8]: Write<S>,
    LongHeader<S>: HasLength + GetType + Encode,
    TX: TransmitStream,
    RX: ReceiveStream,
{
    let keys = match keys.get_local_keys() {
        Some(keys) => keys,
        None => return (0, 0),
    };

    let (pkt_id, pn) = space.next_pkt_no();
    let max_header_size = header.size() + 2; // 2 bytes reserved for packet length, max 16KB
    let pn_size = pn.size();
    let (mut hdr_buf, mut body_buf) = buffer.split_at_mut(max_header_size + pn_size);

    if body_buf.remaining_mut() + pn_size < 20 {
        // Insufficient remaining space, unable to extract enough(16 bytes long) sample to add header protection.
        return (0, 0);
    }

    let mut body_len = space.read(body_buf);
    if body_len == 0 {
        // nothing to send
        return (0, 0);
    }

    unsafe {
        body_buf.advance_mut(body_len);
    }
    let mut length = body_len + pn.size();
    if length < 20 {
        // The sample requires at least 16 bytes, so the length must be at least 20 bytes.
        // If it is not enough, Padding(0x0) needs to be added.
        body_buf.put_bytes(0x0, 20 - length);
        body_len = 20 - pn_size;
        length = 20;
    }

    let mut offset = 0;
    if length < 0x40 {
        match fill_policy {
            FillPolicy::Misalignment => {
                // Misalignment padding: If it is less than 64 bytes, ignore the first byte and start
                // padding the header from the second byte. Do the same when sending packets.
                offset = 1;
                unsafe {
                    hdr_buf.advance_mut(1);
                }
                hdr_buf.put_long_header(&header);
                hdr_buf.put_varint(&VarInt::from_u64(length as u64).unwrap());
            }
            FillPolicy::Redundancy => {
                // Redundant encoding VarInt: If it is less than 64 bytes, use 2 bytes to encode the
                // length. The first byte is 0x40, meaning VarInt is 2 bytes long, and the second byte is the actual length.
                hdr_buf.put_long_header(&header);
                hdr_buf.put_u8(0x40);
                hdr_buf.put_u8(length as u8);
            }
        }
    } else {
        hdr_buf.put_long_header(&header);
        hdr_buf.put_varint(&VarInt::from_u64(length as u64).unwrap());
    }
    hdr_buf.put_packet_number(pn);
    debug_assert!(hdr_buf.is_empty());

    let header_size = max_header_size - offset;
    let header_and_pn_size = header_size + pn_size;
    let pkt_size = header_and_pn_size + body_len;
    let pkt_buffer = &mut buffer[offset..pkt_size];
    // encode pn length in the first byte
    let clear_bits = LongClearBits::with_pn_size(pn_size);
    pkt_buffer[0] |= clear_bits.deref();

    // encrypt packet payload
    let (header, body) = pkt_buffer.split_at_mut(header_and_pn_size);
    keys.deref()
        .local
        .packet
        .encrypt_in_place(pkt_id, header, body)
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

pub fn read_1rtt_data_and_encrypt(
    buffer: &mut [u8],
    header: OneRttHeader,
    keys: ArcOneRttKeys,
    space: ArcSpace<ArcOutput, Streams>,
) -> usize {
    let (hpk, pk) = match keys.get_local_keys() {
        Some(keys) => keys,
        None => return 0,
    };

    let (pkt_id, pn) = space.next_pkt_no();
    let header_size = header.size();
    let pn_size = pn.size();
    let (mut hdr_buf, body_buf) = buffer.split_at_mut(header_size + pn_size);

    if body_buf.remaining_mut() + pn_size < 20 {
        // Insufficient remaining space, unable to extract enough(16 bytes long) sample to add header protection.
        return 0;
    }

    let body_len = space.read(body_buf);
    if body_len == 0 {
        return 0;
    }

    hdr_buf.put_one_rtt_header(&header);
    hdr_buf.put_packet_number(pn);
    debug_assert!(hdr_buf.is_empty());

    let header_and_pn_size = header_size + pn_size;
    let pkt_size = header_and_pn_size + body_len;
    let pkt_buffer = &mut buffer[0..pkt_size];
    // encode pn length in the first byte
    let (key_phase, pk) = pk.lock().unwrap().get_local();
    let mut clear_bits = ShortClearBits::with_pn_size(pn_size);
    clear_bits.set_key_phase(key_phase);
    pkt_buffer[0] |= *clear_bits;

    // encrypt packet payload
    let (header, body) = pkt_buffer.split_at_mut(header_and_pn_size);
    pk.deref().encrypt_in_place(pkt_id, header, body).unwrap();

    // add header protection
    let (header, pn_and_body) = pkt_buffer.split_at_mut(header_size);
    let (pn_max, sample) = pn_and_body.split_at_mut(4);
    hpk.deref()
        .encrypt_in_place(sample, &mut header[0], &mut pn_max[..pn_size])
        .unwrap();

    pkt_size
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
