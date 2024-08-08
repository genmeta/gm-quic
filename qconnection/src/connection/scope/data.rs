use bytes::Bytes;
use futures::{channel::mpsc, StreamExt};
use qbase::{
    error::{Error as QuicError, ErrorKind},
    flow,
    frame::{
        AckFrame, BeFrame, DataFrame, Frame, FrameReader, PathChallengeFrame, PathResponseFrame,
        ReliableFrame, RetireConnectionIdFrame, StreamFrame,
    },
    handshake::Handshake,
    packet::{
        decrypt::{
            decrypt_packet, remove_protection_of_long_packet, remove_protection_of_short_packet,
        },
        header::GetType,
        keys::{ArcKeys, ArcOneRttKeys},
    },
};
use qrecovery::{
    reliable::{ArcReliableFrameDeque, GuaranteedFrame},
    space::{DataSpace, Epoch},
    streams::{crypto::CryptoStream, DataStreams},
};
use qunreliable::DatagramFlow;

use crate::{
    connection::{transmit::data::DataSpaceReader, CidEvent, CidRegistry, PacketEntry, RcvdPacket},
    error::ConnError,
    path::{ArcPath, SendBuffer},
    pipe,
};

#[derive(Clone)]
pub struct DataScope {
    pub zero_rtt_keys: ArcKeys,
    pub one_rtt_keys: ArcOneRttKeys,
    pub space: DataSpace,
    pub crypto_stream: CryptoStream,
    pub zero_rtt_packets_entry: PacketEntry,
    pub one_rtt_packets_entry: PacketEntry,
}

impl DataScope {
    pub fn new(zero_rtt_packets_entry: PacketEntry, one_rtt_packets_entry: PacketEntry) -> Self {
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
        rcvd_0rtt_packets: RcvdPacket,
        rcvd_1rtt_packets: RcvdPacket,
        cid_event_entry: mpsc::UnboundedSender<CidEvent>,
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

        let on_recv_retire_cid_frame = {
            let local_cids = cid_registry.local.clone();
            let error = conn_error.clone();
            move |frame: &RetireConnectionIdFrame| match local_cids.recv_retire_cid_frame(frame) {
                Ok(Some((cid, new_cid))) => {
                    let _ = cid_event_entry.unbounded_send(CidEvent::Retire(cid));
                    let _ = cid_event_entry.unbounded_send(CidEvent::New(new_cid));
                }
                Ok(None) => {}
                Err(e) => {
                    error.on_error(e);
                }
            }
        };

        // Assemble the pipelines of frame processing
        // TODO: impl endpoint router
        // pipe rcvd_new_token_frames
        pipe!(rcvd_max_data_frames |> flow_ctrl.sender, recv_max_data_frame);
        pipe!(rcvd_data_blocked_frames |> flow_ctrl.recver, recv_data_blocked_frame);
        pipe!(@error(conn_error) rcvd_new_cid_frames |> cid_registry.remote, recv_new_cid_frame);
        pipe!(rcvd_retire_cid_frames |> on_recv_retire_cid_frame);
        pipe!(@error(conn_error) rcvd_handshake_done_frames |> *handshake, recv_handshake_done_frame);
        pipe!(rcvd_crypto_frames |> self.crypto_stream.incoming(), recv_crypto_frame);
        pipe!(@error(conn_error) rcvd_stream_ctrl_frames |> *streams, recv_stream_control);
        pipe!(@error(conn_error) rcvd_datagram_frames |> *datagrams, recv_datagram);
        pipe!(rcvd_ack_frames |> on_ack);

        self.handle_stream_frame_with_flow_ctrl(
            streams,
            flow_ctrl,
            conn_error.clone(),
            rcvd_stream_frames,
        );

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
        mut rcvd_packets: RcvdPacket,
        dispatch_frame: impl Fn(Frame, &ArcPath) + Send + 'static,
        conn_error: ConnError,
    ) {
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.zero_rtt_keys.clone();
            async move {
                while let Some((mut packet, path)) = rcvd_packets.next().await {
                    let pty = packet.header.get_type();
                    let Some(keys) = keys.get_remote_keys().await else {
                        break;
                    };
                    let undecoded_pn = match remove_protection_of_long_packet(
                        keys.remote.header.as_ref(),
                        packet.bytes.as_mut(),
                        packet.offset,
                    ) {
                        Ok(Some(pn)) => pn,
                        Ok(None) => continue,
                        Err(_e) => {
                            // conn_error.on_error(e);
                            return;
                        }
                    };

                    let pn = match rcvd_pkt_records.decode_pn(undecoded_pn) {
                        Ok(pn) => pn,
                        // TooOld/TooLarge/HasRcvd
                        Err(_e) => continue,
                    };
                    let body_offset = packet.offset + undecoded_pn.size();
                    decrypt_packet(
                        keys.remote.packet.as_ref(),
                        pn,
                        packet.bytes.as_mut(),
                        body_offset,
                    )
                    .unwrap();
                    let body = packet.bytes.split_off(body_offset);
                    match FrameReader::new(body.freeze(), pty).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame, &path);
                            Ok(is_ack_packet || is_ack_eliciting)
                        },
                    ) {
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
        mut rcvd_packets: RcvdPacket,
        dispatch_frame: impl Fn(Frame, &ArcPath) + Send + 'static,
        conn_error: ConnError,
    ) {
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.one_rtt_keys.clone();
            async move {
                while let Some((mut packet, path)) = rcvd_packets.next().await {
                    let pty = packet.header.get_type();
                    let Some((hpk, pk)) = keys.get_remote_keys().await else {
                        break;
                    };
                    let (undecoded_pn, key_phase) = match remove_protection_of_short_packet(
                        hpk.as_ref(),
                        packet.bytes.as_mut(),
                        packet.offset,
                    ) {
                        Ok(Some(pn)) => pn,
                        Ok(None) => continue,
                        Err(_e) => {
                            // conn_error.on_error(e);
                            return;
                        }
                    };

                    let pn = match rcvd_pkt_records.decode_pn(undecoded_pn) {
                        Ok(pn) => pn,
                        // TooOld/TooLarge/HasRcvd
                        Err(_e) => continue,
                    };
                    let body_offset = packet.offset + undecoded_pn.size();
                    let pk = pk.lock().unwrap().get_remote(key_phase, pn);
                    decrypt_packet(pk.as_ref(), pn, packet.bytes.as_mut(), body_offset).unwrap();
                    let body = packet.bytes.split_off(body_offset);
                    match FrameReader::new(body.freeze(), pty).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame, &path);
                            Ok(is_ack_packet || is_ack_eliciting)
                        },
                    ) {
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

    pub fn handle_stream_frame_with_flow_ctrl(
        &self,
        streams: &DataStreams,
        flow_ctrl: &flow::FlowController,
        conn_error: ConnError,
        mut rcvd_stream_frames: mpsc::UnboundedReceiver<(StreamFrame, Bytes)>,
    ) {
        // Increasing Flow Control Limits
        tokio::spawn({
            let flow_ctrl = flow_ctrl.clone();
            let frames = streams.reliable_frame_deque.clone();
            async move {
                while let Some(frame) = flow_ctrl.recver().incr_limit().await {
                    frames.lock_guard().push_back(ReliableFrame::MaxData(frame));
                }
            }
        });

        // Handling Stream Frames
        tokio::spawn({
            let streams = streams.clone();
            let flow_ctrl = flow_ctrl.clone();
            let error = conn_error.clone();

            async move {
                while let Some(frame) = rcvd_stream_frames.next().await {
                    match streams.recv_data(&frame) {
                        Ok(new_data_size) => {
                            if let Err(e) = flow_ctrl.recver().on_new_rcvd(new_data_size) {
                                ConnError::on_error(
                                    &error,
                                    QuicError::new(
                                        ErrorKind::FlowControl,
                                        frame.0.frame_type(),
                                        format!("{} flow control overflow: {}", frame.0.id, e),
                                    ),
                                );
                            }
                        }
                        Err(e) => {
                            ConnError::on_error(&error, e);
                        }
                    }
                }
            }
        });
    }

    pub fn reader(
        &self,
        challenge_sndbuf: SendBuffer<PathChallengeFrame>,
        response_sndbuf: SendBuffer<PathResponseFrame>,
        reliable_frames: ArcReliableFrameDeque,
        data_streams: DataStreams,
        datagrams: DatagramFlow,
    ) -> DataSpaceReader {
        DataSpaceReader {
            space: self.space.clone(),
            zero_rtt_keys: self.zero_rtt_keys.clone(),
            one_rtt_keys: self.one_rtt_keys.clone(),
            challenge_sndbuf,
            response_sndbuf,
            crypto_stream_outgoing: self.crypto_stream.outgoing(),
            reliable_frames,
            data_streams,
            datagrams,
        }
    }
}
