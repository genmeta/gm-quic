use futures::{channel::mpsc, StreamExt};
use qbase::{
    flow,
    frame::{AckFrame, DataFrame, Frame, FrameReader},
    handshake::Handshake,
    packet::{
        header::GetType,
        keys::{ArcKeys, ArcOneRttKeys},
    },
};
use qrecovery::{
    reliable::GuaranteedFrame,
    space::{DataSpace, Epoch},
    streams::{crypto::CryptoStream, DataStreams},
};
use qunreliable::DatagramFlow;

use crate::{
    connection::{
        decode_long_header_packet, decode_short_header_packet, CidRegistry, OneRttPacketEntry,
        RcvdOneRttPacket, RcvdZeroRttPacket, ZeroRttPacketEntry,
    },
    error::ConnError,
    path::ArcPath,
    pipe,
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
                    path.on_ack(Epoch::Data, &ack_frame);
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
                    path.recv_challenge(challenge);
                }
                Frame::Response(response) => {
                    path.recv_response(response);
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

                    let dispath_result =
                        FrameReader::new(payload, pty).try_fold(false, |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame, &path);
                            Ok(is_ack_packet || is_ack_eliciting)
                        });

                    match dispath_result {
                        Ok(is_ack_packet) => {
                            rcvd_pkt_records.register_pn(pn);
                            path.on_recv_pkt(Epoch::Data, pn, is_ack_packet);
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
                            path.on_recv_pkt(Epoch::Data, pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });
    }
}
