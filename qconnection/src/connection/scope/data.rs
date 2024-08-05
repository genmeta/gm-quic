use std::{
    ops::Deref,
    sync::{Arc, Mutex},
    time::Instant,
};

use bytes::BufMut;
use futures::{channel::mpsc, StreamExt};
use qbase::{
    cid::ConnectionId,
    flow,
    frame::{AckFrame, DataFrame, Frame, FrameReader, PathChallengeFrame, PathResponseFrame},
    handshake::Handshake,
    packet::{
        header::{Encode, GetType, WriteLongHeader, WriteOneRttHeader},
        keys::{ArcKeys, ArcOneRttKeys, OneRttPacketKeys},
        KeyPhaseBit, LongClearBits, LongHeaderBuilder, OneRttHeader, ShortClearBits, SpinBit,
        WritePacketNumber,
    },
    util::Burst,
};
use qrecovery::{
    reliable::{ArcReliableFrameDeque, GuaranteedFrame},
    space::{DataSpace, Epoch},
    streams::{
        crypto::{CryptoStream, CryptoStreamOutgoing},
        DataStreams,
    },
};
use qunreliable::DatagramFlow;
use rustls::quic::HeaderProtectionKey;

use crate::{
    connection::{
        decode_long_header_packet, decode_short_header_packet, CidRegistry, OneRttPacketEntry,
        RcvdOneRttPacket, RcvdZeroRttPacket, ZeroRttPacketEntry,
    },
    error::ConnError,
    path::{ArcPath, PathFrameBuffer},
    pipe,
    transmit::{read_long_header_and_encrypt, read_short_header_and_encrypt, FillPolicy},
};

pub struct DataScope {
    pub zero_rtt_keys: ArcKeys,
    pub one_rtt_keys: ArcOneRttKeys,
    pub space: DataSpace,
    pub crypto_stream: CryptoStream,
    pub zero_rtt_packets_entry: ZeroRttPacketEntry,
    pub one_rtt_packets_entry: OneRttPacketEntry,
}

impl DataScope {
    pub fn new(
        zero_rtt_packets_entry: ZeroRttPacketEntry,
        one_rtt_packets_entry: OneRttPacketEntry,
    ) -> Self {
        Self {
            zero_rtt_keys: ArcKeys::new_pending(),
            one_rtt_keys: ArcOneRttKeys::new_pending(),
            space: DataSpace::with_capacity(16),
            crypto_stream: CryptoStream::new(0, 0),
            zero_rtt_packets_entry,
            one_rtt_packets_entry,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build(
        &self,
        handshake: &Handshake,
        streams: &DataStreams,
        datagrams: &DatagramFlow,
        cid_registry: &CidRegistry,
        flow_ctrl: &flow::FlowController,
        rcvd_0rtt_packets: RcvdZeroRttPacket,
        rcvd_1rtt_packets: RcvdOneRttPacket,
        conn_error: ConnError,
    ) {
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();
        // 连接级的
        let (max_data_frames_entry, rcvd_max_data_frames) = mpsc::unbounded();
        let (data_blocked_frames_entry, rcvd_data_blocked_frames) = mpsc::unbounded();
        let (new_cid_frames_entry, rcvd_new_cid_frames) = mpsc::unbounded();
        let (retire_cid_frames_entry, rcvd_retire_cid_frames) = mpsc::unbounded();
        let (handshake_done_frames_entry, rcvd_handshake_done_frames) = mpsc::unbounded();
        let (new_token_frames_entry, _rcvd_new_token_frames) = mpsc::unbounded();
        // 数据级的
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (stream_ctrl_frames_entry, rcvd_stream_ctrl_frames) = mpsc::unbounded();
        let (stream_frames_entry, rcvd_stream_frames) = mpsc::unbounded();
        let (datagram_frames_entry, rcvd_datagram_frames) = mpsc::unbounded();

        let dispatch_data_frame = {
            let conn_error = conn_error.clone();
            move |frame: Frame, path: &ArcPath| match frame {
                Frame::Close(ccf) => {
                    conn_error.on_ccf_rcvd(&ccf);
                }
                Frame::Ack(ack_frame) => {
                    path.lock_guard().on_ack(Epoch::Data, &ack_frame);
                    _ = ack_frames_entry.unbounded_send(ack_frame);
                }
                Frame::NewToken(new_token) => {
                    _ = new_token_frames_entry.unbounded_send(new_token);
                }
                Frame::MaxData(max_data) => {
                    _ = max_data_frames_entry.unbounded_send(max_data);
                }
                Frame::NewConnectionId(new_cid) => {
                    _ = new_cid_frames_entry.unbounded_send(new_cid);
                }
                Frame::RetireConnectionId(retire_cid) => {
                    _ = retire_cid_frames_entry.unbounded_send(retire_cid);
                }
                Frame::HandshakeDone(hs_done) => {
                    _ = handshake_done_frames_entry.unbounded_send(hs_done);
                }
                Frame::DataBlocked(data_blocked) => {
                    _ = data_blocked_frames_entry.unbounded_send(data_blocked);
                }
                Frame::Challenge(challenge) => {
                    path.lock_guard().recv_challenge(challenge);
                }
                Frame::Response(response) => {
                    path.lock_guard().recv_response(response);
                }
                Frame::Stream(stream_ctrl) => {
                    _ = stream_ctrl_frames_entry.unbounded_send(stream_ctrl);
                }
                Frame::Data(DataFrame::Stream(stream), data) => {
                    _ = stream_frames_entry.unbounded_send((stream, data));
                }
                Frame::Data(DataFrame::Crypto(crypto), data) => {
                    _ = crypto_frames_entry.unbounded_send((crypto, data));
                }
                Frame::Datagram(datagram, data) => {
                    _ = datagram_frames_entry.unbounded_send((datagram, data));
                }
                _ => {}
            }
        };
        let on_ack = {
            let data_streams = streams.clone();
            let crypto_stream_outgoing = self.crypto_stream.outgoing();
            let sent_pkt_records = self.space.sent_packets();
            move |ack_frame: &AckFrame| {
                let mut recv_guard = sent_pkt_records.receive();
                recv_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in recv_guard.on_pkt_acked(pn) {
                        match frame {
                            GuaranteedFrame::Data(DataFrame::Stream(stream_frame)) => {
                                data_streams.on_data_acked(stream_frame)
                            }
                            GuaranteedFrame::Data(DataFrame::Crypto(crypto)) => {
                                crypto_stream_outgoing.on_data_acked(&crypto)
                            }
                            _ => { /* nothing to do */ }
                        }
                    }
                }
            }
        };

        // Assemble the pipelines of frame processing
        // TODO: impl endpoint router
        // pipe rcvd_new_token_frames
        pipe!(rcvd_max_data_frames |> flow_ctrl.sender, recv_max_data_frame);
        pipe!(rcvd_data_blocked_frames |> flow_ctrl.recver, recv_data_blocked_frame);
        pipe!(@error(conn_error) rcvd_new_cid_frames |> cid_registry.remote, recv_new_cid_frame);
        pipe!(@error(conn_error) rcvd_retire_cid_frames |> cid_registry.local, recv_retire_cid_frame);
        pipe!(@error(conn_error) rcvd_handshake_done_frames |> *handshake, recv_handshake_done_frame);
        pipe!(rcvd_crypto_frames |> self.crypto_stream.incoming(), recv_crypto_frame);
        pipe!(@error(conn_error) rcvd_stream_ctrl_frames |> *streams, recv_stream_control);
        pipe!(@error(conn_error) rcvd_stream_frames |> *streams, recv_data);
        pipe!(@error(conn_error) rcvd_datagram_frames |> *datagrams, recv_datagram);
        pipe!(rcvd_ack_frames |> on_ack);

        self.parse_rcvd_0rtt_packet_and_dispatch_frames(
            rcvd_0rtt_packets,
            dispatch_data_frame.clone(),
            conn_error.clone(),
        );
        self.parse_rcvd_1rtt_packet_and_dispatch_frames(
            rcvd_1rtt_packets,
            dispatch_data_frame,
            conn_error,
        );
    }

    fn parse_rcvd_0rtt_packet_and_dispatch_frames(
        &self,
        mut rcvd_packets: RcvdZeroRttPacket,
        dispatch_frame: impl Fn(Frame, &ArcPath) + Send + 'static,
        conn_error: ConnError,
    ) {
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.zero_rtt_keys.clone();
            async move {
                while let Some((packet, path)) = rcvd_packets.next().await {
                    let pty = packet.header.get_type();
                    let decode_pn = |pn| rcvd_pkt_records.decode_pn(pn).ok();
                    let (pn, payload) =
                        match decode_long_header_packet(packet, &keys, decode_pn).await {
                            Some((pn, payload)) => (pn, payload),
                            None => return,
                        };

                    match FrameReader::new(payload, pty).try_fold(false, |is_ack_packet, frame| {
                        let (frame, is_ack_eliciting) = frame?;
                        dispatch_frame(frame, &path);
                        Ok(is_ack_packet || is_ack_eliciting)
                    }) {
                        Ok(is_ack_packet) => {
                            rcvd_pkt_records.register_pn(pn);
                            path.lock_guard()
                                .on_recv_pkt(Epoch::Data, pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });
    }

    fn parse_rcvd_1rtt_packet_and_dispatch_frames(
        &self,
        mut rcvd_packets: RcvdOneRttPacket,
        dispatch_frame: impl Fn(Frame, &ArcPath) + Send + 'static,
        conn_error: ConnError,
    ) {
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.one_rtt_keys.clone();
            async move {
                while let Some((packet, path)) = rcvd_packets.next().await {
                    let pty = packet.header.get_type();
                    let decode_pn = |pn| rcvd_pkt_records.decode_pn(pn).ok();
                    let (pn, payload) =
                        match decode_short_header_packet(packet, &keys, decode_pn).await {
                            Some((pn, payload)) => (pn, payload),
                            None => return,
                        };
                    match FrameReader::new(payload, pty).try_fold(false, |is_ack_packet, frame| {
                        let (frame, is_ack_eliciting) = frame?;
                        dispatch_frame(frame, &path);
                        Ok(is_ack_packet || is_ack_eliciting)
                    }) {
                        Ok(is_ack_packet) => {
                            rcvd_pkt_records.register_pn(pn);
                            path.lock_guard()
                                .on_recv_pkt(Epoch::Data, pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });
    }

    pub fn reader(
        &self,
        key_phase: KeyPhaseBit,
        path_challenge_buffer: PathFrameBuffer<PathChallengeFrame>,
        path_response_buffer: PathFrameBuffer<PathResponseFrame>,
        reliable_frames: ArcReliableFrameDeque,
        data_streams: DataStreams,
        datagrams: DatagramFlow,
    ) -> DataSpaceReader {
        DataSpaceReader {
            space: self.space.clone(),
            zero_rtt_keys: self.zero_rtt_keys.clone(),
            key_phase,
            one_rtt_keys: self.one_rtt_keys.clone(),
            path_challenge_buffer,
            path_response_buffer,
            crypto_stream_outgoing: self.crypto_stream.outgoing(),
            reliable_frames,
            data_streams,
            datagrams,
        }
    }
}

pub struct DataSpaceReader {
    space: DataSpace,
    zero_rtt_keys: ArcKeys,
    key_phase: KeyPhaseBit,
    one_rtt_keys: ArcOneRttKeys,
    // 数据源
    path_challenge_buffer: PathFrameBuffer<PathChallengeFrame>,
    path_response_buffer: PathFrameBuffer<PathResponseFrame>,
    crypto_stream_outgoing: CryptoStreamOutgoing,
    reliable_frames: ArcReliableFrameDeque,
    data_streams: DataStreams,
    datagrams: DatagramFlow,
    // 为了各个流的公平性，包括不可靠数据帧，需要额外维护一些信息
}

impl DataSpaceReader {
    pub fn one_rtt_keys(
        &self,
    ) -> Option<(Arc<dyn HeaderProtectionKey>, Arc<Mutex<OneRttPacketKeys>>)> {
        self.one_rtt_keys.get_local_keys()
    }

    pub fn read_1rtt(
        &self,
        burst: &mut Burst,
        buf: &mut [u8],
        dcid: ConnectionId,
        spin: SpinBit,
        ack_pkt: Option<(u64, Instant)>,
        keys: (Arc<dyn HeaderProtectionKey>, Arc<Mutex<OneRttPacketKeys>>),
    ) -> Option<(u64, bool, usize, bool, Option<u64>)> {
        // 0. 检查1rtt keys是否有效，没有则回退到0rtt包
        // 1. 生成包头，根据包头大小，配合burst、剩余空间，检查是否能发送，不能的话，直接返回
        let hdr = OneRttHeader { spin, dcid };
        let b = burst.measure(hdr.size(), buf.remaining_mut())?;
        let (mut hdr_buf, payload_buf) = buf.split_at_mut(hdr.size());

        // 2. 锁定发送记录器，生成pn，如果pn大小不够，直接返回
        let sent_pkt_records = self.space.sent_packets();
        let mut send_guard = sent_pkt_records.send();
        let (pn, pkt_no) = send_guard.next_pn();
        let mut b = b.measure(pkt_no.size(), payload_buf.remaining_mut())?;
        let (mut pn_buf, mut body_buf) = payload_buf.split_at_mut(pkt_no.size());

        let mut is_ack_eliciting = false;
        let mut in_flight = false;
        let body_size = body_buf.remaining_mut();

        // 3. 检查PathFrameBuffer，尝试写，但发送记录并不记录，若写入一个字节，则burst开始记录
        let n = self.path_challenge_buffer.read(&mut b, body_buf);
        if n > 0 {
            send_guard.record_trivial();
            is_ack_eliciting = true;
            in_flight = true;
            body_buf = &mut body_buf[n..];
        }
        let n = self.path_response_buffer.read(&mut b, body_buf);
        if n > 0 {
            send_guard.record_trivial();
            is_ack_eliciting = true;
            in_flight = true;
            body_buf = &mut body_buf[n..];
        }

        // 4. 检查是否需要发送Ack，若是，且符合（burst + buf）节制，生成ack并写入，但发送记录并不记录
        let mut sent_ack = None;
        if let Some((largest, recv_time)) = ack_pkt {
            let rcvd_pkt_records = self.space.rcvd_packets();
            let n = rcvd_pkt_records.read_ack_frame_util(&mut b, body_buf, largest, recv_time)?;
            send_guard.record_trivial();
            sent_ack = Some(largest);
            body_buf = &mut body_buf[n..];
        }

        // 5. 检查可靠帧，若有且符合（burst + buf）节制，写入，burst、发包记录都记录
        while let Some((frame, n)) = self.reliable_frames.try_read(&mut b, body_buf) {
            send_guard.record_frame(GuaranteedFrame::Reliable(frame));
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            in_flight = true;
        }

        // 6. 检查NewToken，是否需要发送

        // 7. 象征性地检查一下CryptoStream
        while let Some((frame, n)) = self.crypto_stream_outgoing.try_read_data(&mut b, body_buf) {
            send_guard.record_frame(GuaranteedFrame::Data(DataFrame::Crypto(frame)));
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            in_flight = true;
        }

        // 8. 检查DataStreams是否需要发送，若有，且符合（burst + buf）节制，写入，burst、发包记录都记录
        while let Some((_frame, n)) = self.datagrams.try_read_datagram(&mut b, body_buf) {
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            in_flight = true;
        }

        // 9. 检查Datagrams是否需要发送，若有，且符合(burst + buf) 节制，写入，burst、发包记录都记录
        while let Some((_frame, n)) = self.datagrams.try_read_datagram(&mut b, body_buf) {
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            in_flight = true;
        }
        drop(send_guard); // 持有这把锁的时间越短越好，毕竟下面的加密可能会有点耗时

        // 10. 任何时候，（burst、buf）不再能写入任何数据后，停止写入
        //     若有东西发，记录burst变化，后面肯定要发送了，反馈给拥塞控制，抗放大攻击(该空间不涉及流控)
        *burst = b;

        // 11 保护包头，加密数据
        hdr_buf.put_one_rtt_header(&hdr);
        let mut clear_bits = ShortClearBits::from_pn(&pkt_no);
        clear_bits.set_key_phase(self.key_phase);
        hdr_buf[0] |= *clear_bits;
        pn_buf.put_packet_number(pkt_no);
        let body_size = body_size - body_buf.remaining_mut();
        let sent_size = hdr.size() + 2 + pkt_no.size() + body_size;
        read_short_header_and_encrypt(buf, &hdr, pn, pkt_no.size(), body_size, &keys);
        // 0RTT包不能发送Ack
        Some((pn, is_ack_eliciting, sent_size, in_flight, sent_ack))
    }

    pub fn read_0rtt(
        &self,
        burst: &mut Burst,
        buf: &mut [u8],
        scid: ConnectionId,
        dcid: ConnectionId,
    ) -> Option<(u64, bool, usize, bool)> {
        // 1. 检查0rtt keys是否有效，没有则结束
        let k = self.zero_rtt_keys.get_local_keys()?;

        // 2. 生成包头，预留2字节len，根据包头大小，配合burst、剩余空间，检查是否能发送，不能的话，直接返回
        let hdr = LongHeaderBuilder::with_cid(dcid, scid).zero_rtt();
        let b = burst.measure(hdr.size() + 2, buf.remaining_mut())?;
        let (mut hdr_buf, payload_buf) = buf.split_at_mut(hdr.size() + 2);

        // 3. 锁定发送记录器，生成pn，如果pn大小不够，直接返回
        let sent_pkt_records = self.space.sent_packets();
        let mut send_guard = sent_pkt_records.send();
        let (pn, pkt_no) = send_guard.next_pn();
        let mut b = b.measure(pkt_no.size(), payload_buf.remaining_mut())?;
        let (mut pn_buf, mut body_buf) = payload_buf.split_at_mut(pkt_no.size());

        let mut is_ack_eliciting = false;
        let mut in_flight = false;
        let body_size = body_buf.remaining_mut();

        // 4. 只检查PathChallengeBuffer，尝试写，但发送记录并不记录，若写入一个帧，则burst开始记录
        //    可能没有Challenge帧，所以仍要继续
        let n = self.path_challenge_buffer.read(&mut b, body_buf);
        if n > 0 {
            send_guard.record_trivial();
            is_ack_eliciting = true;
            in_flight = true;
            body_buf = &mut body_buf[n..];
        }

        // 5. 检查可靠帧，若有且符合（burst + buf）节制，写入，burst、发包记录都记录
        while let Some((frame, n)) = self.reliable_frames.try_read(&mut b, body_buf) {
            send_guard.record_frame(GuaranteedFrame::Reliable(frame));
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            in_flight = true;
        }

        // 6. 检查DataStreams是否需要发送，若有，且符合（burst + buf）节制，写入，burst、发包记录都记录
        // TODO: 要注意和Datagrams的公平了
        while let Some((frame, n)) = self.data_streams.try_read_data(&mut b, body_buf) {
            send_guard.record_frame(GuaranteedFrame::Data(DataFrame::Stream(frame)));
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            in_flight = true;
        }

        // 7. 检查Datagrams是否需要发送，若有，且符合(burst + buf) 节制，写入，burst、发包记录都记录
        while let Some((_frame, n)) = self.datagrams.try_read_datagram(&mut b, body_buf) {
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            in_flight = true;
        }
        drop(send_guard); // 持有这把锁的时间越短越好，毕竟下面的加密可能会有点耗时

        // 8. 记录burst变化，后面肯定要发送了，反馈给拥塞控制，抗放大攻击(该空间不涉及流控)
        *burst = b;

        // 9. 填充，保护头部，加密
        hdr_buf.put_long_header(&hdr);
        let clear_bits = LongClearBits::from_pn(&pkt_no);
        hdr_buf[0] |= clear_bits.deref();
        pn_buf.put_packet_number(pkt_no);
        let body_size = body_size - body_buf.remaining_mut();
        let sent_size = hdr.size() + 2 + pkt_no.size() + body_size;
        read_long_header_and_encrypt(
            buf,
            &hdr,
            pn,
            pkt_no.size(),
            body_size,
            &k,
            FillPolicy::Redundancy,
        );
        // 0RTT包不能发送Ack
        Some((pn, is_ack_eliciting, sent_size, in_flight))
    }
}
