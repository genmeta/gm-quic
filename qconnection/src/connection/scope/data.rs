use std::sync::Arc;

use bytes::{BufMut, Bytes};
use futures::{channel::mpsc, StreamExt};
use qbase::{
    cid::ConnectionId,
    error::{Error as QuicError, ErrorKind},
    flow,
    frame::{
        io::WriteFrame, AckFrame, BeFrame, ConnectionCloseFrame, Frame, FrameReader,
        PathChallengeFrame, PathResponseFrame, ReceiveFrame, ReliableFrame, SendFrame,
        StreamCtlFrame, StreamFrame,
    },
    handshake::Handshake,
    packet::{
        decrypt::{
            decrypt_packet, remove_protection_of_long_packet, remove_protection_of_short_packet,
        },
        encrypt::{encode_short_first_byte, encrypt_packet, protect_header},
        header::{
            short::{io::WriteShortHeader, OneRttHeader},
            EncodeHeader, GetType,
        },
        keys::{ArcKeys, ArcOneRttKeys, ArcOneRttPacketKeys, HeaderProtectionKeys},
        number::WritePacketNumber,
        r#type::Type,
        DataPacket, PacketNumber,
    },
    token::ArcTokenRegistry,
};
use qcongestion::{CongestionControl, MayLoss, RetirePktRecord, MSS};
use qrecovery::{
    crypto::{CryptoStream, CryptoStreamOutgoing},
    reliable::{ArcRcvdPktRecords, ArcReliableFrameDeque, GuaranteedFrame},
    space::{DataSpace, Epoch},
};
use qunreliable::DatagramFlow;
use tokio::{sync::Notify, task::JoinHandle};

use super::any;
use crate::{
    connection::{transmit::data::DataSpaceReader, CidRegistry, DataStreams, RcvdPackets},
    error::ConnError,
    path::{ArcPathes, Path, SendBuffer},
    pipe,
    router::Router,
};

#[derive(Clone)]
pub struct DataScope {
    pub zero_rtt_keys: ArcKeys,
    pub one_rtt_keys: ArcOneRttKeys,
    pub space: DataSpace,
    pub crypto_stream: CryptoStream,
}

impl Default for DataScope {
    fn default() -> Self {
        Self {
            zero_rtt_keys: ArcKeys::new_pending(),
            one_rtt_keys: ArcOneRttKeys::new_pending(),
            space: DataSpace::with_capacity(16),
            crypto_stream: CryptoStream::new(4096, 4096),
        }
    }
}

impl DataScope {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        &self,
        pathes: &ArcPathes,
        handshake: &Handshake<ArcReliableFrameDeque>,
        reliable_frames: &ArcReliableFrameDeque,
        streams: &DataStreams,
        datagrams: &DatagramFlow,
        cid_registry: &CidRegistry,
        flow_ctrl: &flow::FlowController,
        notify: &Arc<Notify>,
        conn_error: &ConnError,
        rcvd_0rtt_packets: RcvdPackets,
        rcvd_1rtt_packets: RcvdPackets,
        recv_new_token: ArcTokenRegistry,
    ) -> (JoinHandle<RcvdPackets>, JoinHandle<RcvdPackets>) {
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();
        // 连接级的
        let (max_data_frames_entry, rcvd_max_data_frames) = mpsc::unbounded();
        let (data_blocked_frames_entry, rcvd_data_blocked_frames) = mpsc::unbounded();
        let (new_cid_frames_entry, rcvd_new_cid_frames) = mpsc::unbounded();
        let (retire_cid_frames_entry, rcvd_retire_cid_frames) = mpsc::unbounded();
        let (handshake_done_frames_entry, rcvd_handshake_done_frames) = mpsc::unbounded();
        let (new_token_frames_entry, rcvd_new_token_frames) = mpsc::unbounded();
        // 数据级的
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (stream_ctrl_frames_entry, rcvd_stream_ctrl_frames) = mpsc::unbounded();
        let (stream_frames_entry, rcvd_stream_frames) = mpsc::unbounded();
        let (datagram_frames_entry, rcvd_datagram_frames) = mpsc::unbounded();

        let dispatch_data_frame = {
            let conn_error = conn_error.clone();
            move |frame: Frame, pty: Type, path: &Path| match frame {
                Frame::Ack(f) => {
                    path.cc.on_ack(Epoch::Data, &f);
                    _ = ack_frames_entry.unbounded_send(f)
                }
                Frame::NewToken(f) => _ = new_token_frames_entry.unbounded_send(f),
                Frame::MaxData(f) => _ = max_data_frames_entry.unbounded_send(f),
                Frame::NewConnectionId(f) => _ = new_cid_frames_entry.unbounded_send(f),
                Frame::RetireConnectionId(f) => _ = retire_cid_frames_entry.unbounded_send(f),
                Frame::HandshakeDone(f) => _ = handshake_done_frames_entry.unbounded_send(f),
                Frame::DataBlocked(f) => _ = data_blocked_frames_entry.unbounded_send(f),
                Frame::Challenge(f) => path.recv_challenge(f),
                Frame::Response(f) => path.recv_response(f),
                Frame::StreamCtl(f) => _ = stream_ctrl_frames_entry.unbounded_send(f),
                Frame::Stream(f, data) => _ = stream_frames_entry.unbounded_send((f, data)),
                Frame::Crypto(f, bytes) => _ = crypto_frames_entry.unbounded_send((f, bytes)),
                Frame::Datagram(f, data) => _ = datagram_frames_entry.unbounded_send((f, data)),
                Frame::Close(f) if matches!(pty, Type::Short(_)) => conn_error.on_ccf_rcvd(&f),
                _ => {}
            }
        };
        let on_data_acked = {
            let data_streams = streams.clone();
            let crypto_stream_outgoing = self.crypto_stream.outgoing();
            let sent_pkt_records = self.space.sent_packets();
            move |ack_frame: &AckFrame| {
                let mut recv_guard = sent_pkt_records.recv();
                recv_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in recv_guard.on_pkt_acked(pn) {
                        match frame {
                            GuaranteedFrame::Stream(stream_frame) => {
                                data_streams.on_data_acked(stream_frame)
                            }
                            GuaranteedFrame::Crypto(crypto_frame) => {
                                crypto_stream_outgoing.on_data_acked(&crypto_frame)
                            }
                            GuaranteedFrame::Reliable(ReliableFrame::Stream(
                                StreamCtlFrame::ResetStream(reset_frame),
                            )) => data_streams.on_reset_acked(reset_frame),
                            _ => { /* nothing to do */ }
                        }
                    }
                }
            }
        };

        // Assemble the pipelines of frame processing
        // TODO: pipe rcvd_new_token_frames
        let local_cids_with_router = Router::revoke(cid_registry.local.clone());
        pipe!(rcvd_retire_cid_frames |> local_cids_with_router, recv_frame);
        pipe!(@error(conn_error) rcvd_new_cid_frames |> cid_registry.remote, recv_frame);
        pipe!(rcvd_max_data_frames |> flow_ctrl.sender, recv_frame);
        pipe!(rcvd_data_blocked_frames |> flow_ctrl.recver, recv_frame);
        pipe!(@error(conn_error) rcvd_handshake_done_frames |> *handshake, recv_frame);
        pipe!(@error(conn_error) rcvd_crypto_frames |> self.crypto_stream.incoming(), recv_frame);
        pipe!(@error(conn_error) rcvd_stream_ctrl_frames |> *streams, recv_frame);
        // pipe!(@error(conn_error) rcvd_stream_frames |> receive_stream_frame);
        pipe!(@error(conn_error) rcvd_datagram_frames |> *datagrams, recv_frame);
        pipe!(rcvd_ack_frames |> on_data_acked);
        pipe!(rcvd_new_token_frames |> recv_new_token,recv_frame);

        self.handle_stream_frame_with_flow_ctrl(
            reliable_frames,
            streams,
            flow_ctrl,
            conn_error.clone(),
            rcvd_stream_frames,
        );

        let join_handler0 = self.parse_rcvd_0rtt_packet_and_dispatch_frames(
            rcvd_0rtt_packets,
            pathes.clone(),
            dispatch_data_frame.clone(),
            notify.clone(),
            conn_error.clone(),
        );
        let join_handler1 = self.parse_rcvd_1rtt_packet_and_dispatch_frames(
            rcvd_1rtt_packets,
            pathes.clone(),
            dispatch_data_frame,
            notify.clone(),
            conn_error.clone(),
        );
        (join_handler0, join_handler1)
    }

    fn parse_rcvd_0rtt_packet_and_dispatch_frames(
        &self,
        mut rcvd_packets: RcvdPackets,
        pathes: ArcPathes,
        dispatch_frame: impl Fn(Frame, Type, &Path) + Send + 'static,
        notify: Arc<Notify>,
        conn_error: ConnError,
    ) -> JoinHandle<RcvdPackets> {
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.zero_rtt_keys.clone();
            async move {
                while let Some((mut packet, pathway, usc)) = any(rcvd_packets.next(), &notify).await
                {
                    let pty = packet.header.get_type();
                    let Some(keys) = any(keys.get_remote_keys(), &notify).await else {
                        break;
                    };
                    let undecoded_pn = match remove_protection_of_long_packet(
                        keys.remote.header.as_ref(),
                        packet.bytes.as_mut(),
                        packet.offset,
                    ) {
                        Ok(Some(pn)) => pn,
                        Ok(None) => continue,
                        Err(invalid_reserved_bits) => {
                            conn_error.on_error(invalid_reserved_bits.into());
                            break;
                        }
                    };

                    let pn = match rcvd_pkt_records.decode_pn(undecoded_pn) {
                        Ok(pn) => pn,
                        // TooOld/TooLarge/HasRcvd
                        Err(_e) => continue,
                    };
                    let body_offset = packet.offset + undecoded_pn.size();
                    let decrypted = decrypt_packet(
                        keys.remote.packet.as_ref(),
                        pn,
                        packet.bytes.as_mut(),
                        body_offset,
                    );
                    let Ok(pkt_len) = decrypted else { continue };

                    let path = pathes.get_or_create(pathway, usc);
                    path.on_rcvd(packet.bytes.len());

                    let _header = packet.bytes.split_to(body_offset);
                    packet.bytes.truncate(pkt_len);

                    match FrameReader::new(packet.bytes.freeze(), pty).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame, pty, &path);
                            Ok(is_ack_packet || is_ack_eliciting)
                        },
                    ) {
                        Ok(is_ack_packet) => {
                            rcvd_pkt_records.register_pn(pn);
                            path.cc.on_pkt_rcvd(Epoch::Data, pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
                rcvd_packets
            }
        })
    }

    fn parse_rcvd_1rtt_packet_and_dispatch_frames(
        &self,
        mut rcvd_packets: RcvdPackets,
        pathes: ArcPathes,
        dispatch_frame: impl Fn(Frame, Type, &Path) + Send + 'static,
        notify: Arc<Notify>,
        conn_error: ConnError,
    ) -> JoinHandle<RcvdPackets> {
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.one_rtt_keys.clone();
            async move {
                while let Some((mut packet, pathway, usc)) = any(rcvd_packets.next(), &notify).await
                {
                    let pty = packet.header.get_type();
                    let Some((hpk, pk)) = any(keys.get_remote_keys(), &notify).await else {
                        break;
                    };
                    let (undecoded_pn, key_phase) = match remove_protection_of_short_packet(
                        hpk.as_ref(),
                        packet.bytes.as_mut(),
                        packet.offset,
                    ) {
                        Ok(Some(pn)) => pn,
                        Ok(None) => continue,
                        Err(invalid_reserved_bits) => {
                            conn_error.on_error(invalid_reserved_bits.into());
                            break;
                        }
                    };

                    let pn = match rcvd_pkt_records.decode_pn(undecoded_pn) {
                        Ok(pn) => pn,
                        // TooOld/TooLarge/HasRcvd
                        Err(_e) => continue,
                    };
                    let body_offset = packet.offset + undecoded_pn.size();
                    let pk = pk.lock_guard().get_remote(key_phase, pn);
                    let decrypted =
                        decrypt_packet(pk.as_ref(), pn, packet.bytes.as_mut(), body_offset);
                    let Ok(pkt_len) = decrypted else { continue };

                    let path = pathes.get_or_create(pathway, usc);
                    path.on_rcvd(packet.bytes.len());

                    let _header = packet.bytes.split_to(body_offset);
                    packet.bytes.truncate(pkt_len);

                    match FrameReader::new(packet.bytes.freeze(), pty).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame, pty, &path);
                            Ok(is_ack_packet || is_ack_eliciting)
                        },
                    ) {
                        Ok(is_ack_packet) => {
                            rcvd_pkt_records.register_pn(pn);
                            path.cc.on_pkt_rcvd(Epoch::Data, pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
                rcvd_packets
            }
        })
    }

    pub fn handle_stream_frame_with_flow_ctrl(
        &self,
        reliable_frames: &ArcReliableFrameDeque,
        streams: &DataStreams,
        flow_ctrl: &flow::FlowController,
        conn_error: ConnError,
        mut rcvd_stream_frames: mpsc::UnboundedReceiver<(StreamFrame, Bytes)>,
    ) {
        // Sender Would Block
        tokio::spawn({
            let flow_ctrl = flow_ctrl.clone();
            let reliable_frames = reliable_frames.clone();
            async move {
                while let Ok(frame) = flow_ctrl.sender().would_block().await {
                    reliable_frames.send_frame([frame]);
                }
            }
        });

        //  Recver Increasing Flow Control Limits
        tokio::spawn({
            let flow_ctrl = flow_ctrl.clone();
            let reliable_frames = reliable_frames.clone();
            async move {
                while let Some(frame) = flow_ctrl.recver().incr_limit().await {
                    reliable_frames.send_frame([frame]);
                }
            }
        });

        // Handling Stream Frames
        tokio::spawn({
            let streams = streams.clone();
            let flow_ctrl = flow_ctrl.clone();
            let conn_error = conn_error.clone();
            async move {
                while let Some(data_frame) = rcvd_stream_frames.next().await {
                    match streams.recv_data(&data_frame) {
                        Ok(new_data_size) => {
                            if let Err(e) = flow_ctrl.recver().on_new_rcvd(new_data_size) {
                                conn_error.on_error(QuicError::new(
                                    ErrorKind::FlowControl,
                                    data_frame.0.frame_type(),
                                    format!("{} flow control overflow: {}", data_frame.0.id, e),
                                ));
                            }
                        }
                        Err(e) => conn_error.on_error(e),
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
        streams: DataStreams,
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
            streams,
            datagrams,
        }
    }
}

impl RetirePktRecord for DataScope {
    fn retire(&self, pn: u64) {
        self.space.rcvd_packets().write().retire(pn);
    }
}

#[derive(Clone)]
pub struct DataMayLoss {
    space: DataSpace,
    reliable_frames: ArcReliableFrameDeque,
    data_streams: DataStreams,
    outgoing: CryptoStreamOutgoing,
}

impl DataMayLoss {
    pub fn new(
        space: DataSpace,
        reliable_frames: ArcReliableFrameDeque,
        data_streams: DataStreams,
        outgoing: CryptoStreamOutgoing,
    ) -> Self {
        Self {
            space,
            reliable_frames,
            data_streams,
            outgoing,
        }
    }
}
impl MayLoss for DataMayLoss {
    fn may_loss(&self, pn: u64) {
        for frame in self.space.sent_packets().recv().may_loss_pkt(pn) {
            match frame {
                GuaranteedFrame::Stream(f) => self.data_streams.may_loss_data(&f),
                GuaranteedFrame::Reliable(f) => self.reliable_frames.send_frame([f]),
                GuaranteedFrame::Crypto(f) => self.outgoing.may_loss_data(&f),
            }
        }
    }
}

#[derive(Clone)]
pub struct ClosingOneRttScope {
    keys: (HeaderProtectionKeys, ArcOneRttPacketKeys),
    rcvd_pkt_records: ArcRcvdPktRecords,
    // 发包时用得着
    next_sending_pn: (u64, PacketNumber),
}

impl ClosingOneRttScope {
    pub fn assemble_ccf_packet(
        &self,
        buf: &mut [u8; MSS],
        ccf: &ConnectionCloseFrame,
        dcid: ConnectionId,
    ) -> usize {
        let (hpk, pk) = &self.keys;
        let hpk = &hpk.local;

        let spin = Default::default();
        let hdr = OneRttHeader { spin, dcid };
        let (mut hdr_buf, payload_tag) = buf.split_at_mut(hdr.size());
        let payload_tag_len = payload_tag.len();
        let tag_len = pk.tag_len();
        let payload_buf = &mut payload_tag[..payload_tag_len - tag_len];

        let (pn, encoded_pn) = self.next_sending_pn;
        let (mut pn_buf, mut body_buf) = payload_buf.split_at_mut(encoded_pn.size());

        let body_size = body_buf.remaining_mut();

        body_buf.put_frame(ccf);

        let hdr_len = hdr_buf.len();
        let pn_len = pn_buf.len();
        let mut body_len = body_size - body_buf.remaining_mut();
        if pn_len + body_len + tag_len < 20 {
            let padding_len = 20 - pn_len - body_len - tag_len;
            body_buf.put_bytes(0, padding_len);
            body_len += padding_len;
        }
        let sent_size = hdr_len + pn_len + body_len + tag_len;

        hdr_buf.put_short_header(&hdr);
        pn_buf.put_packet_number(encoded_pn);

        let (key_phase, pk) = pk.lock_guard().get_local();
        encode_short_first_byte(&mut buf[0], pn_len, key_phase);
        encrypt_packet(pk.as_ref(), pn, &mut buf[..sent_size], hdr_len + pn_len);
        protect_header(hpk.as_ref(), &mut buf[..sent_size], hdr_len, pn_len);

        sent_size
    }
}

impl TryFrom<DataScope> for ClosingOneRttScope {
    type Error = ();

    fn try_from(data: DataScope) -> Result<Self, Self::Error> {
        let Some(keys) = data.one_rtt_keys.invalid() else {
            return Err(());
        };
        let rcvd_pkt_records = data.space.rcvd_packets();
        let next_sending_pn = data.space.sent_packets().send().next_pn();

        Ok(Self {
            keys,
            rcvd_pkt_records,
            next_sending_pn,
        })
    }
}

impl super::RecvPacket for ClosingOneRttScope {
    fn has_rcvd_ccf(&self, mut packet: DataPacket) -> bool {
        let (undecoded_pn, key_phase) = match remove_protection_of_short_packet(
            self.keys.0.remote.as_ref(),
            packet.bytes.as_mut(),
            packet.offset,
        ) {
            Ok(Some(pn)) => pn,
            _ => return false,
        };

        let pn = match self.rcvd_pkt_records.decode_pn(undecoded_pn) {
            Ok(pn) => pn,
            // TooOld/TooLarge/HasRcvd
            Err(_e) => return false,
        };
        let body_offset = packet.offset + undecoded_pn.size();
        let pk = self.keys.1.lock_guard().get_remote(key_phase, pn);
        Self::decrypt_and_parse(pk.as_ref(), pn, packet, body_offset)
    }
}
