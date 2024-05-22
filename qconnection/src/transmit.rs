use bytes::BufMut;
use qbase::packet::{
    header::{long::LongHeader, Encode, GetType, HasLength, Write, WriteLongHeader},
    keys::ArcKeys,
    WritePacketNumber,
};
use qrecovery::{
    crypto::CryptoStream,
    space::{SpaceIO, TrySend},
    streams::NoStreams,
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

pub fn read_space_and_encrypt<S>(
    buffer: &mut [u8],
    mut header: LongHeader<S>,
    fill_policy: FillPolicy,
    keys: ArcKeys,
    space: SpaceIO<CryptoStream, NoStreams>,
) -> (usize, usize)
where
    for<'a> &'a mut [u8]: Write<S>,
    LongHeader<S>: HasLength + GetType + Encode,
{
    let keys = match keys.get_local_keys() {
        Some(keys) => keys,
        None => return (0, 0),
    };

    let (pkt_id, pn) = space.next_pkt_no();
    let max_header_size = header.max_size();
    let pn_size = pn.size();
    let (mut hdr_buf, mut body_buf) = buffer.split_at_mut(max_header_size + pn_size);

    let mut len = space.try_send(body_buf);
    if len > 0 {
        unsafe {
            body_buf.advance_mut(len);
        }
        let mut length = len + pn.size();
        if length < 20 {
            // The sample requires at least 16 bytes, so the length must be at least 20 bytes.
            // If it is not enough, Padding(0x0) needs to be added.
            body_buf.put_bytes(0x0, 20 - length);
            len = 20 - pn_size;
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
                    header.set_length(length);
                    hdr_buf.put_long_header(&header);
                }
                FillPolicy::Redundancy => {
                    // Redundant encoding VarInt: If it is less than 64 bytes, use 2 bytes to encode the
                    // length. The first byte is 0x01, and the second byte is the actual length.
                    header.set_length(0x01);
                    hdr_buf.put_long_header(&header);
                    hdr_buf.put_u8(length as u8);
                }
            }
            hdr_buf.put_packet_number(pn);
        }

        // encrypt packet payload
        let header_size = max_header_size - offset;
        let header_and_pn_size = header_size + pn_size;
        let pkt_size = header_and_pn_size + len;
        let pkt_buffer = &mut buffer[offset..pkt_size];
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
    } else {
        // nothing to send
        (0, 0)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
