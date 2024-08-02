use std::{ops::Deref, time::Instant};

use bytes::BufMut;
use qbase::{
    frame::{
        io::WriteAckFrame,
        BeFrame, CryptoFrame,
        DataFrame::{Crypto, Stream},
    },
    packet::{
        header::{Encode, GetType, LongHeader, Write, WriteLongHeader, WriteOneRttHeader},
        keys::{ArcKeys, ArcOneRttKeys},
        LongClearBits, OneRttHeader, ShortClearBits, WritePacketNumber,
    },
    util::Burst,
    varint::{VarInt, WriteVarInt},
};
use qrecovery::{
    reliable::{
        rcvdpkt::ArcRcvdPktRecords, sentpkt::SendGuard, ArcReliableFrameDeque, GuaranteedFrame,
    },
    space::{DataSpace, Epoch, HandshakeSpace, InitialSpace},
    streams::{crypto::CryptoStream, DataStreams},
};

use crate::connection::raw::RawConnection;

#[derive(Clone)]
pub(super) struct InitialReader {
    pub(super) space: InitialSpace,
    pub(super) stream: CryptoStream,
    pub(super) keys: ArcKeys,
}

#[derive(Clone)]
pub(super) struct HandshakeReader {
    space: HandshakeSpace,
    stream: CryptoStream,
    keys: ArcKeys,
}

#[derive(Clone)]
pub(super) struct DataReader {
    space: DataSpace,
    crypto_stream: CryptoStream,
    data_streams: DataStreams,
    reliable_frames_deque: ArcReliableFrameDeque,
    one_rtt_keys: ArcOneRttKeys,
}

#[derive(Clone)]
pub(super) struct SpaceReaders {
    initial: InitialReader,
    handshake: HandshakeReader,
    data: DataReader,
}

impl SpaceReaders {
    pub(super) fn new(connection: &RawConnection) -> Self {
        let initial = InitialReader {
            space: connection.initial.space.clone(),
            stream: connection.initial.crypto_stream.clone(),
            keys: connection.initial.keys.clone(),
        };
        let handshake: HandshakeReader = HandshakeReader {
            space: connection.hs.space.clone(),
            stream: connection.hs.crypto_stream.clone(),
            keys: connection.hs.keys.clone(),
        };

        let data = DataReader {
            space: connection.data.space.clone(),
            crypto_stream: connection.data.crypto_stream.clone(),
            data_streams: connection.streams.clone(),
            reliable_frames_deque: connection.reliable_frames.clone(),
            one_rtt_keys: connection.data.one_rtt_keys.clone(),
        };

        Self {
            initial,
            handshake,
            data,
        }
    }

    pub(super) fn retire(&self, epoch: Epoch, ack: Vec<u64>) {
        todo!("indacate ack")
    }

    pub(super) fn may_loss(&self, epoch: Epoch, loss: Vec<u64>) {
        todo!("may loss")
    }

    pub(super) fn read_long_header_space<T>(
        &self,
        buffer: &mut [u8],
        header: &LongHeader<T>,
        burst: &mut Burst,
        epoch: Epoch,
        ack_pkt: Option<(u64, Instant)>,
    ) -> (usize, u64, bool)
    where
        for<'a> &'a mut [u8]: Write<T>,
        LongHeader<T>: GetType + Encode,
    {
        let (space, stream, keys) = match epoch {
            Epoch::Initial => (
                &self.initial.space,
                &self.initial.stream,
                &self.initial.keys,
            ),
            Epoch::Handshake => (
                &self.handshake.space,
                &self.handshake.stream,
                &self.handshake.keys,
            ),
            Epoch::Data => unreachable!(),
        };

        let max_header_size = header.size() + 2;

        if burst.available() < max_header_size || buffer.remaining_mut() < max_header_size {
            return (0, 0, false);
        }
        let (_, body_buf) = buffer.split_at_mut(max_header_size);
        let send_record = space.sent_packets();
        // read pn
        let mut guard = send_record.send();
        // TODO: 没数据先不写 PN
        let (pn, pn_size) = read_pn(body_buf, burst, &mut guard);
        let body_buf = &mut body_buf[pn_size..];

        // read ack
        let mut written = read_ack_frame(body_buf, burst, ack_pkt, &space.rcvd_packets());
        let body_buf = &mut body_buf[written..];

        let mut is_ack_eliciting = false;
        // read cropto frame
        written += if let Some((crypto_frame, written)) =
            stream.outgoing().try_read_data(burst, body_buf)
        {
            is_ack_eliciting = true;
            guard.record_frame(crypto_frame);
            written
        } else {
            0
        };

        let body_size = written + pn_size;
        let fill_policy = FillPolicy::Redundancy;
        let pkt_size = read_long_header_and_encrypt(
            buffer,
            header,
            pn,
            pn_size,
            body_size,
            &keys.get_local_keys().unwrap(),
            fill_policy,
        );

        (pkt_size, pn, is_ack_eliciting)
    }

    pub fn read_one_rtt_space(
        &mut self,
        buffer: &mut [u8],
        burst: &mut Burst,
        header: &OneRttHeader,
        ack_pkt: Option<(u64, Instant)>,
    ) -> (usize, u64, bool) {
        let reader = &mut self.data;
        let max_header_size = header.size() + 2;
        if burst.available() < max_header_size || buffer.remaining_mut() < max_header_size {
            return (0, 0, false);
        }
        let (_, body_buf) = buffer.split_at_mut(max_header_size);
        let origin = body_buf.remaining_mut();
        let send_record = reader.space.sent_packets();

        // read pn
        let mut guard = send_record.send();
        let (pn, pn_size) = read_pn(body_buf, burst, &mut guard);
        let body_buf = &mut body_buf[pn_size..];

        // read ack
        let written = read_ack_frame(body_buf, burst, ack_pkt, &reader.space.rcvd_packets());
        let mut body_buf = &mut body_buf[written..];

        // read path challenge and response
        // TODO: 至少填充到 1200 字节
        // read reliable frame
        let (written, is_ack_eliciting) = read_reliable_frame(
            body_buf,
            burst,
            &mut reader.reliable_frames_deque,
            &mut guard,
        );

        let body_buf = &mut body_buf[written..];
        // read cropto frame
        let written = if let Some((crypto_frame, written)) = reader
            .crypto_stream
            .outgoing()
            .try_read_data(burst, body_buf)
        {
            guard.record_frame(GuaranteedFrame::Data(Crypto(crypto_frame)));
            written
        } else {
            0
        };

        let body_buf = &mut body_buf[written..];
        // read data frame
        let written =
            if let Some((frame, written)) = reader.data_streams.try_read_data(burst, body_buf) {
                guard.record_frame(GuaranteedFrame::Data(Stream(frame)));
                written
            } else {
                0
            };

        let body_buf = &mut body_buf[written..];
        let body_size = origin - body_buf.remaining_mut();
        let pkt_size = read_short_header_and_encrypt(
            buffer,
            header,
            pn,
            pn_size,
            body_size,
            &reader.one_rtt_keys,
        );
        (pkt_size, pn, is_ack_eliciting)
    }
}

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

pub fn read_pn<T>(mut buf: &mut [u8], burst: &mut Burst, guard: &mut SendGuard<T>) -> (u64, usize) {
    let (pn, encoded_pn) = guard.next_pn();
    if buf.remaining_mut() > encoded_pn.size() && burst.available() > encoded_pn.size() {
        buf.put_packet_number(encoded_pn);
        burst.post_write(encoded_pn.size());
        return (pn, encoded_pn.size());
    }
    (0, 0)
}

// TODO: 只包含 ack frame 的 packe 不计入拥塞控制
pub fn read_ack_frame(
    mut buf: &mut [u8],
    burst: &mut Burst,
    ack_pkt: Option<(u64, Instant)>,
    rcvd_pkt_records: &ArcRcvdPktRecords,
) -> usize {
    let ack_pkt = if let Some(ack_pkt) = ack_pkt {
        ack_pkt
    } else {
        return 0;
    };

    let remain = buf.remaining_mut();
    let ack_frame = rcvd_pkt_records.gen_ack_frame_util(ack_pkt, remain);

    if buf.remaining_mut() > ack_frame.encoding_size()
        && burst.available() > ack_frame.encoding_size()
    {
        buf.put_ack_frame(&ack_frame);
        let written = remain - buf.remaining_mut();
        burst.post_write(written);
        written
    } else {
        0
    }
}

pub fn read_crypto_stream(
    buf: &mut [u8],
    burst: &mut Burst,
    stream: &mut CryptoStream,
    guard: &mut SendGuard<CryptoFrame>,
) -> usize {
    if let Some((crypto_frame, written)) = stream.outgoing().try_read_data(burst, buf) {
        guard.record_frame(crypto_frame);
        return written;
    }
    0
}

pub fn read_reliable_frame(
    buf: &mut [u8],
    burst: &mut Burst,
    reliable_frame_queue: &mut ArcReliableFrameDeque,
    guard: &mut SendGuard<GuaranteedFrame>,
) -> (usize, bool) {
    let is_ack_eliciting = false;
    let written = 0;
    let queue = reliable_frame_queue.lock_guard();
    while let Some(frame) = queue.front() {
        todo!("read_reliable_frame");
        //  let available = std::cmp::min(limit.available(), buf.remaining_mut());
        // if available < frame.max_encoding_size() && available < frame.encoding_size() {
        //     break;
        // }
        // if frame.is_ack_eliciting() {
        //     is_ack_eliciting = true;
        // }
        // buf.put_frame(frame);
        // written += frame.encoding_size();
        // let frame = queue.pop_front().unwrap();
        // limit.record_write(frame.encoding_size());
        let frame = queue.pop_front().unwrap();
        guard.record_frame(GuaranteedFrame::Reliable(frame));
    }
    (written, is_ack_eliciting)
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

pub fn read_short_header_and_encrypt(
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
