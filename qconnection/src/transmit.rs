use std::{
    ops::{Deref, DerefMut},
    time::Instant,
};

use bytes::BufMut;
use qbase::{
    frame::{
        io::{WriteAckFrame, WriteFrame},
        BeFrame, CryptoFrame, ReliableFrame,
    },
    packet::{
        header::{Encode, GetType, LongHeader, Write, WriteLongHeader, WriteOneRttHeader},
        keys::{ArcKeys, ArcOneRttKeys},
        HandshakeHeader, InitialHeader, LongClearBits, OneRttHeader, ShortClearBits,
        WritePacketNumber,
    },
    util::TransportLimit,
    varint::{VarInt, WriteVarInt},
};
use qrecovery::{
    reliable::{rcvdpkt::ArcRcvdPktRecords, sentpkt::SendGuard, ArcReliableFrameDeque},
    space::{DataSpace, HandshakeSpace, InitialSpace},
    streams::{crypto::CryptoStream, DataStreams},
};

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

fn read_pn<T>(
    mut buf: &mut [u8],
    limit: &mut TransportLimit,
    guard: &mut SendGuard<T>,
) -> (u64, usize) {
    let (pn, encoded_pn) = guard.next_pn();
    if buf.remaining_mut() > encoded_pn.size() && limit.available() > encoded_pn.size() {
        buf.put_packet_number(encoded_pn);
        limit.record_write(encoded_pn.size());
        return (pn, encoded_pn.size());
    }
    (0, 0)
}

// TODO: 只包含 ack frame 的 packe 不计入拥塞控制
fn read_ack_frame<T>(
    mut buf: &mut [u8],
    limit: &mut TransportLimit,
    ack_pkt: Option<(u64, Instant)>,
    rcvd_pkt_records: ArcRcvdPktRecords,
) -> Option<usize> {
    let remain = buf.remaining_mut();

    let ack_frame = rcvd_pkt_records.gen_ack_frame_util(ack_pkt?, remain);
    if buf.remaining_mut() > ack_frame.encoding_size()
        && limit.available() > ack_frame.encoding_size()
    {
        buf.put_ack_frame(&ack_frame);
        let written = remain - buf.remaining_mut();
        limit.record_write(written);
        Some(written)
    } else {
        Some(0)
    }
}

fn read_crypto_stream(
    buf: &mut [u8],
    limit: &mut TransportLimit,
    stream: &mut CryptoStream,
    guard: &mut SendGuard<CryptoFrame>,
) -> usize {
    if let Some((crypto_frame, written)) = stream.try_read_data(limit, buf) {
        let send_record = guard.deref_mut().deref_mut();
        send_record.deref_mut().push_back(crypto_frame);
        return written;
    }
    0
}

fn read_reliable_frame(
    mut buf: &mut [u8],
    limit: &mut TransportLimit,
    reliable_frame_queue: &mut ArcReliableFrameDeque,
    guard: &mut SendGuard<ReliableFrame>,
) -> (usize, bool) {
    let mut is_ack_eliciting = false;
    let mut written = 0;
    let mut queue = reliable_frame_queue.lock_guard();
    while let Some(frame) = queue.front() {
        let available = limit.available();
        if available < frame.max_encoding_size() && available < frame.encoding_size() {
            break;
        }
        if frame.is_ack_eliciting() {
            is_ack_eliciting = true;
        }
        buf.put_frame(frame);
        written += frame.encoding_size();
        let frame = queue.pop_front().unwrap();
        limit.record_write(frame.encoding_size());
        let send_record = guard.deref_mut().deref_mut();
        send_record.deref_mut().push_back(frame);
    }
    (written, is_ack_eliciting)
}

fn read_data_stream(buf: &mut [u8], limit: &mut TransportLimit, stream: &mut DataStreams) -> usize {
    // TODO: send guard 记录 stream frame
    if let Some((_, written)) = stream.try_read_data(limit, buf) {
        return written;
    }
    0
}

fn read_long_header_and_encrypt<T>(
    buffer: &mut [u8],
    header: &LongHeader<T>,
    pn: u64,
    pn_size: usize,
    body_size: usize,
    keys: &ArcKeys,
    fill_policy: FillPolicy,
) -> usize
where
    for<'a> &'a mut [u8]: Write<T>,
    LongHeader<T>: GetType + Encode,
{
    let keys = match keys.get_local_keys() {
        Some(keys) => keys,
        None => return 0,
    };
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

    let header_size = max_header_size - offset;
    let header_and_pn_size = header_size + pn_size;
    let pkt_size = header_size + body_size;
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

    pkt_size
}

fn read_short_header_and_encrypt(
    mut buffer: &mut [u8],
    header: &OneRttHeader,
    pn: u64,
    pn_size: usize,
    body_size: usize,
    keys: &ArcOneRttKeys,
) -> usize {
    let (hpk, pk) = match keys.get_local_keys() {
        Some(keys) => keys,
        None => return 0,
    };

    let header_size = header.size();

    buffer.put_one_rtt_header(header);

    let header_and_pn_size = header_size + pn_size;
    let pkt_size = header_size + body_size;
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

#[derive(Clone)]
struct InitialReader {
    space: InitialSpace,
    stream: CryptoStream,
    keys: ArcKeys,
    header: InitialHeader,
}

struct HandshakeReader {
    space: HandshakeSpace,
    stream: CryptoStream,
    keys: ArcKeys,
    header: HandshakeHeader,
}

struct DataReader {
    data_space: DataSpace,
    data_crypto_stream: CryptoStream,
    data_streams: DataStreams,
    data_reliable_frames_deque: ArcReliableFrameDeque,

    one_rtt_keys: ArcOneRttKeys,
    one_rtt_header: OneRttHeader,
}
