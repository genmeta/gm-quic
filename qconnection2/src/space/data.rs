use std::{convert::Infallible, sync::Arc};

use bytes::BufMut as _;
use qbase::{
    cid,
    error::Error,
    frame::{
        AckFrame, BeFrame as _, ConnectionCloseFrame, Frame, FrameReader, PathChallengeFrame,
        PathResponseFrame, ReceiveFrame as _, ReliableFrame, StreamCtlFrame,
    },
    packet::{
        self,
        header::{long::ZeroRttHeader, short::OneRttHeader, GetType as _},
        keys, signal, MarshalFrame as _,
    },
    param, sid, token,
};
use qcongestion::CongestionControl as _;
use qrecovery::{
    crypto, journal,
    reliable::{self, GuaranteedFrame},
};

use crate::{builder, conn, event, path, tx, util::subscribe};

#[derive(Clone)]
pub struct Space {
    zero_rtt_keys: keys::ArcKeys,
    one_rtt_keys: keys::ArcOneRttKeys,
    journal: journal::DataJournal,
    crypto_stream: crypto::CryptoStream,
    reliable_frames: reliable::ArcReliableFrameDeque,
    streams: conn::DataStreams,
    datagrams: qunreliable::DatagramFlow,
}

impl Space {
    pub fn new(
        role: sid::Role,
        reliable_frames: reliable::ArcReliableFrameDeque,
        local_params: &param::CommonParameters,
        streams_ctrl: Box<dyn sid::ControlConcurrency>,
    ) -> Self {
        let streams =
            conn::DataStreams::new(role, local_params, streams_ctrl, reliable_frames.clone());
        Self {
            zero_rtt_keys: keys::ArcKeys::new_pending(),
            one_rtt_keys: keys::ArcOneRttKeys::new_pending(),
            journal: journal::DataJournal::with_capacity(16),
            crypto_stream: crypto::CryptoStream::new(4096, 4096),
            reliable_frames,
            streams,
            datagrams: qunreliable::DatagramFlow::new(1024),
        }
    }

    pub fn has_early_data(&self) -> bool {
        self.zero_rtt_keys.get_local_keys().is_some() // && ...
    }

    pub fn try_assemble_0rtt<'b>(
        &self,
        tx: &mut tx::Transaction<'_>,
        path_challenge_frames: &path::SendBuffer<PathChallengeFrame>,
        buf: &'b mut [u8],
        fill: bool,
    ) -> Option<(packet::AssembledPacket<'b>, usize)> {
        if self.one_rtt_keys.get_local_keys().is_some() {
            return None;
        }

        let keys = self.zero_rtt_keys.get_local_keys()?;
        let sent_journal = self.journal.of_sent_packets();
        let mut packet = tx::PacketMemory::new(
            packet::header::LongHeaderBuilder::with_cid(tx.dcid(), tx.scid()).zero_rtt(),
            buf,
            keys.local.packet.tag_len(),
            &sent_journal,
        )?;

        path_challenge_frames.try_load_frames_into(&mut packet);
        // TODO: 可以封装在CryptoStream中，当成一个函数
        //      crypto_stream.try_load_data_into(&mut packet);
        let crypto_stream_outgoing = self.crypto_stream.outgoing();
        crypto_stream_outgoing.try_load_data_into(&mut packet);
        // try to load reliable frames into this 0RTT packet to send
        self.reliable_frames.try_load_frames_into(&mut packet);
        // try to load stream frames into this 0RTT packet to send
        let fresh_data = self
            .streams
            .try_load_data_into(&mut packet, tx.flow_limit());
        self.datagrams.try_load_data_into(&mut packet);

        if !packet.is_empty() && fill {
            let remaining = packet.remaining_mut();
            packet.put_bytes(0, remaining);
        }

        let packet: packet::PacketWriter<'b> = packet.try_into().ok()?;
        Some((
            packet.encrypt_long_packet(keys.local.header.as_ref(), keys.local.packet.as_ref()),
            fresh_data,
        ))
    }

    pub fn has_pending_data(&self) -> bool {
        self.one_rtt_keys.get_local_keys().is_some() // && ...
    }

    pub fn try_assemble_1rtt<'b>(
        &self,
        tx: &mut tx::Transaction<'_>,
        spin: signal::SpinBit,
        path_challenge_frames: &path::SendBuffer<PathChallengeFrame>,
        path_response_frames: &path::SendBuffer<PathResponseFrame>,
        buf: &'b mut [u8],
        fill: bool,
    ) -> Option<(packet::AssembledPacket<'b>, Option<u64>, usize)> {
        let (hpk, pk) = self.one_rtt_keys.get_local_keys()?;
        let sent_journal = self.journal.of_sent_packets();
        let mut packet = tx::PacketMemory::new(
            OneRttHeader::new(spin, tx.dcid()),
            buf,
            pk.tag_len(),
            &sent_journal,
        )?;

        let mut ack = None;
        if let Some((largest, rcvd_time)) = tx.need_ack(qbase::Epoch::Data) {
            let rcvd_journal = self.journal.of_rcvd_packets();
            if let Some(ack_frame) =
                rcvd_journal.gen_ack_frame_util(largest, rcvd_time, packet.remaining_mut())
            {
                packet.dump_ack_frame(ack_frame);
                ack = Some(largest);
            }
        }

        path_challenge_frames.try_load_frames_into(&mut packet);
        path_response_frames.try_load_frames_into(&mut packet);
        // TODO: 可以封装在CryptoStream中，当成一个函数
        //      crypto_stream.try_load_data_into(&mut packet);
        let crypto_stream_outgoing = self.crypto_stream.outgoing();
        crypto_stream_outgoing.try_load_data_into(&mut packet);
        // try to load reliable frames into this 1RTT packet to send
        self.reliable_frames.try_load_frames_into(&mut packet);
        // try to load stream frames into this 1RTT packet to send
        let fresh_data = self
            .streams
            .try_load_data_into(&mut packet, tx.flow_limit());
        self.datagrams.try_load_data_into(&mut packet);

        if !packet.is_empty() && fill {
            let remaining = packet.remaining_mut();
            packet.put_bytes(0, remaining);
        }

        let packet: packet::PacketWriter<'b> = packet.try_into().ok()?;
        let pk_guard = pk.lock_guard();
        let (key_phase, pk) = pk_guard.get_local();
        Some((
            packet.encrypt_short_packet(key_phase, hpk.as_ref(), pk.as_ref()),
            ack,
            fresh_data,
        ))
    }

    pub fn try_assemble_ccf_packet<'b>(
        &self,
        dcid: cid::ConnectionId,
        ccf: &ConnectionCloseFrame,
        buf: &'b mut [u8],
    ) -> Option<packet::AssembledPacket<'b>> {
        let (hpk, pk) = self.one_rtt_keys.get_local_keys()?;
        let header = OneRttHeader::new(Default::default(), dcid);
        let sent_journal = self.journal.of_sent_packets();
        let new_packet_guard = sent_journal.new_packet();
        let pn = new_packet_guard.pn();
        let tag_len = pk.tag_len();
        let mut packet_writer = packet::PacketWriter::new(&header, buf, pn, tag_len)?;

        packet_writer.dump_frame(ccf.clone());

        let pk_guard = pk.lock_guard();
        let (key_phase, pk) = pk_guard.get_local();
        Some(packet_writer.encrypt_short_packet(key_phase, hpk.as_ref(), pk.as_ref()))
    }

    pub fn tracker(&self) -> Tracker {
        Tracker {
            journal: self.journal.clone(),
            reliable_frames: self.reliable_frames.clone(),
            streams: self.streams.clone(),
            outgoing: self.crypto_stream.outgoing(),
        }
    }

    pub fn streams(&self) -> &conn::DataStreams {
        &self.streams
    }

    pub fn datagrams(&self) -> &qunreliable::DatagramFlow {
        &self.datagrams
    }

    pub(crate) fn one_rtt_keys(&self) -> &keys::ArcOneRttKeys {
        &self.one_rtt_keys
    }

    pub(crate) fn crypto_stream(&self) -> &crypto::CryptoStream {
        &self.crypto_stream
    }
}

#[derive(Clone)]
pub struct Tracker {
    journal: journal::DataJournal,
    reliable_frames: reliable::ArcReliableFrameDeque,
    streams: conn::DataStreams,
    outgoing: crypto::CryptoStreamOutgoing,
}

impl qcongestion::TrackPackets for Tracker {
    fn may_loss(&self, pn: u64) {
        use qbase::frame::SendFrame;
        for frame in self.journal.of_sent_packets().rotate().may_loss_pkt(pn) {
            match frame {
                GuaranteedFrame::Stream(f) => self.streams.may_loss_data(&f),
                GuaranteedFrame::Reliable(f) => self.reliable_frames.send_frame([f]),
                GuaranteedFrame::Crypto(f) => self.outgoing.may_loss_data(&f),
            }
        }
    }

    fn retire(&self, pn: u64) {
        self.journal.of_rcvd_packets().write().retire(pn);
    }
}

pub struct ZeroRttPacketEntry {
    keys: Arc<rustls::quic::Keys>,
    crypto_stream_incoming: crypto::CryptoStreamIncoming,
    crypto_stream_outgoing: crypto::CryptoStreamOutgoing,
    sent_journal: journal::ArcSentJournal<GuaranteedFrame>,
    rcvd_journal: journal::ArcRcvdJournal,

    streams: conn::DataStreams,
    datagrams: qunreliable::DatagramFlow,
    flow_ctrl: conn::FlowController,
    handshake: conn::Handshake,

    remote_cid_registry: conn::ArcRemoteCids,
    local_cid_registry: conn::ArcLocalCids,

    token_registry: token::ArcTokenRegistry,
}

impl ZeroRttPacketEntry {
    pub async fn new(space: Space, components: builder::Components) -> Option<Self> {
        let keys = space.zero_rtt_keys.get_remote_keys().await?;
        let crypto_stream_incoming = space.crypto_stream.incoming();
        let crypto_stream_outgoing = space.crypto_stream.outgoing();
        let sent_journal = space.journal.of_sent_packets();
        let rcvd_journal = space.journal.of_rcvd_packets();

        let streams = space.streams.clone();
        let datagrams = space.datagrams.clone();
        let flow_ctrl = components.flow_ctrl.clone();
        let handshake = components.handshake.clone();

        let remote_cid_registry = components.cid_registry.remote.clone();
        let local_cid_registry = components.cid_registry.local.clone();

        let token_registry = components.token_registry.clone();

        Some(Self {
            keys,
            crypto_stream_incoming,
            crypto_stream_outgoing,
            sent_journal,
            rcvd_journal,
            streams,
            datagrams,
            flow_ctrl,
            handshake,
            remote_cid_registry,
            local_cid_registry,
            token_registry,
        })
    }

    pub fn dispatch_frame(&self, frame: Frame, path: &path::Path) -> Result<(), Error> {
        let handle_stream_frame_with_flow_control = |data_frame| {
            self.streams
                .recv_data(data_frame)
                .and_then(|new_data_size| {
                    self.flow_ctrl.on_new_rcvd(new_data_size).map_err(|e| {
                        let kind = qbase::error::ErrorKind::FlowControl;
                        let frame_type = data_frame.0.frame_type();
                        let reason = format!("{} flow control overflow: {}", data_frame.0.id, e);
                        Error::new(kind, frame_type, reason)
                    })
                })
        };
        let on_data_acked = {
            let data_streams = self.streams.clone();
            move |ack_frame: &AckFrame| {
                let mut rotate_guard = self.sent_journal.rotate();
                rotate_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in rotate_guard.on_pkt_acked(pn) {
                        match frame {
                            GuaranteedFrame::Stream(stream_frame) => {
                                data_streams.on_data_acked(stream_frame)
                            }
                            GuaranteedFrame::Crypto(crypto_frame) => {
                                self.crypto_stream_outgoing.on_data_acked(&crypto_frame)
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

        match frame {
            Frame::Padding(..) | Frame::Ping(..) => {}
            Frame::Ack(ack) => {
                path.cc().on_ack(qbase::Epoch::Data, &ack);
                on_data_acked(&ack);
            }
            Frame::NewToken(f) => self.token_registry.recv_frame(&f)?,
            Frame::MaxData(f) => self.flow_ctrl.sender.recv_frame(&f)?,
            Frame::NewConnectionId(f) => _ = self.remote_cid_registry.recv_frame(&f)?,
            Frame::RetireConnectionId(f) => _ = self.local_cid_registry.recv_frame(&f)?,
            Frame::HandshakeDone(f) => self.handshake.recv_frame(&f)?,
            Frame::DataBlocked(f) => self.flow_ctrl.recver.recv_frame(&f)?,
            Frame::Challenge(f) => path.recv_frame(&f)?,
            Frame::Response(f) => path.recv_frame(&f)?,
            Frame::StreamCtl(f) => self.streams.recv_frame(&f)?,
            Frame::Stream(f, data) => _ = handle_stream_frame_with_flow_control(&(f, data))?,
            Frame::Crypto(f, data) => self.crypto_stream_incoming.recv_frame(&(f, data))?,
            Frame::Datagram(f, data) => self.datagrams.recv_frame(&(f, data))?,
            Frame::Close(_f) => { /* trustless */ }
        };
        Ok(())
    }
}

type ZeroRttPacket = (ZeroRttHeader, bytes::BytesMut, usize);

impl subscribe::Subscribe<(ZeroRttPacket, &path::Path)> for ZeroRttPacketEntry {
    type Error = Error;

    fn deliver(
        &self,
        ((hdr, pkt, offset), path): (ZeroRttPacket, &path::Path),
    ) -> Result<(), Self::Error> {
        let rcvd_size = pkt.len();
        let (hpk, pk) = (
            self.keys.remote.header.as_ref(),
            self.keys.remote.packet.as_ref(),
        );
        let parsed =
            super::util::parse_long_header_packet(pkt, offset, hpk, pk, &self.rcvd_journal);
        let Some((pn, body_buf)) = parsed else {
            return Ok(());
        };

        path.on_rcvd(rcvd_size);

        let dispatch = |is_ack_packet, frame| {
            let (frame, is_ack_eliciting) = frame?;
            self.dispatch_frame(frame, path)?;
            Result::<bool, Self::Error>::Ok(is_ack_packet || is_ack_eliciting)
        };
        let is_ack_packet = FrameReader::new(body_buf, hdr.get_type()).try_fold(false, dispatch)?;
        path.cc().on_pkt_rcvd(qbase::Epoch::Data, pn, is_ack_packet);
        self.rcvd_journal.register_pn(pn);

        Ok(())
    }
}

pub struct OneRttPacketEntry {
    keys: (
        Arc<dyn rustls::quic::HeaderProtectionKey>,
        keys::ArcOneRttPacketKeys,
    ),
    crypto_stream_incoming: crypto::CryptoStreamIncoming,
    crypto_stream_outgoing: crypto::CryptoStreamOutgoing,
    sent_journal: journal::ArcSentJournal<GuaranteedFrame>,
    rcvd_journal: journal::ArcRcvdJournal,

    streams: conn::DataStreams,
    datagrams: qunreliable::DatagramFlow,
    flow_ctrl: conn::FlowController,
    handshake: conn::Handshake,

    remote_cid_registry: conn::ArcRemoteCids,
    local_cid_registry: conn::ArcLocalCids,

    token_registry: token::ArcTokenRegistry,

    // EventBroker
    event_broker: event::EventBroker,
}

impl OneRttPacketEntry {
    pub async fn new(
        space: Space,
        components: builder::Components,
        event_broker: event::EventBroker,
    ) -> Option<Self> {
        let keys = space.one_rtt_keys.get_remote_keys().await?;
        let crypto_stream_incoming = space.crypto_stream.incoming();
        let crypto_stream_outgoing = space.crypto_stream.outgoing();
        let sent_journal = space.journal.of_sent_packets();
        let rcvd_journal = space.journal.of_rcvd_packets();

        let streams = space.streams.clone();
        let datagrams = space.datagrams.clone();
        let flow_ctrl = components.flow_ctrl.clone();
        let handshake = components.handshake.clone();

        let remote_cid_registry = components.cid_registry.remote.clone();
        let local_cid_registry = components.cid_registry.local.clone();

        let token_registry = components.token_registry.clone();

        let event_broker = event_broker.clone();

        Some(Self {
            keys,
            crypto_stream_incoming,
            crypto_stream_outgoing,
            sent_journal,
            rcvd_journal,
            streams,
            datagrams,
            flow_ctrl,
            handshake,
            remote_cid_registry,
            local_cid_registry,
            token_registry,
            event_broker,
        })
    }

    pub fn dispatch_frame(&self, frame: Frame, path: &path::Path) -> Result<(), Error> {
        let handle_stream_frame_with_flow_control = |data_frame| {
            self.streams
                .recv_data(data_frame)
                .and_then(|new_data_size| {
                    self.flow_ctrl.on_new_rcvd(new_data_size).map_err(|e| {
                        let kind = qbase::error::ErrorKind::FlowControl;
                        let frame_type = data_frame.0.frame_type();
                        let reason = format!("{} flow control overflow: {}", data_frame.0.id, e);
                        Error::new(kind, frame_type, reason)
                    })
                })
        };
        let on_data_acked = {
            let data_streams = self.streams.clone();
            move |ack_frame: &AckFrame| {
                let mut rotate_guard = self.sent_journal.rotate();
                rotate_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in rotate_guard.on_pkt_acked(pn) {
                        match frame {
                            GuaranteedFrame::Stream(stream_frame) => {
                                data_streams.on_data_acked(stream_frame)
                            }
                            GuaranteedFrame::Crypto(crypto_frame) => {
                                self.crypto_stream_outgoing.on_data_acked(&crypto_frame)
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

        use subscribe::Subscribe;
        match frame {
            Frame::Padding(..) | Frame::Ping(..) => {}
            Frame::Ack(ack) => {
                path.cc().on_ack(qbase::Epoch::Data, &ack);
                on_data_acked(&ack);
            }
            Frame::NewToken(f) => self.token_registry.recv_frame(&f)?,
            Frame::MaxData(f) => self.flow_ctrl.sender.recv_frame(&f)?,
            Frame::NewConnectionId(f) => _ = self.remote_cid_registry.recv_frame(&f)?,
            Frame::RetireConnectionId(f) => _ = self.local_cid_registry.recv_frame(&f)?,
            Frame::HandshakeDone(f) => self.handshake.recv_frame(&f)?,
            Frame::DataBlocked(f) => self.flow_ctrl.recver.recv_frame(&f)?,
            Frame::Challenge(f) => path.recv_frame(&f)?,
            Frame::Response(f) => path.recv_frame(&f)?,
            Frame::StreamCtl(f) => self.streams.recv_frame(&f)?,
            Frame::Stream(f, data) => _ = handle_stream_frame_with_flow_control(&(f, data))?,
            Frame::Crypto(f, data) => self.crypto_stream_incoming.recv_frame(&(f, data))?,
            Frame::Datagram(f, data) => self.datagrams.recv_frame(&(f, data))?,
            Frame::Close(f) => _ = self.event_broker.deliver(event::ConnEvent::ReceivedCcf(f)),
        };
        Ok(())
    }
}

type OneRttPacket = (OneRttHeader, bytes::BytesMut, usize);

impl subscribe::Subscribe<(OneRttPacket, &path::Path)> for OneRttPacketEntry {
    type Error = Error;

    fn deliver(
        &self,
        ((hdr, pkt, offset), path): (OneRttPacket, &path::Path),
    ) -> Result<(), Self::Error> {
        let rcvd_size = pkt.len();
        let (hpk, pk) = (self.keys.0.as_ref(), &self.keys.1);
        let parsed =
            super::util::parse_short_header_packet(pkt, offset, hpk, pk, &self.rcvd_journal);
        let Some((pn, body_buf)) = parsed else {
            return Ok(());
        };

        path.on_rcvd(rcvd_size);

        let dispatch = |is_ack_packet, frame| {
            let (frame, is_ack_eliciting) = frame?;
            self.dispatch_frame(frame, path)?;
            Result::<bool, Self::Error>::Ok(is_ack_packet || is_ack_eliciting)
        };
        let is_ack_packet = FrameReader::new(body_buf, hdr.get_type()).try_fold(false, dispatch)?;
        path.cc().on_pkt_rcvd(qbase::Epoch::Data, pn, is_ack_packet);
        self.rcvd_journal.register_pn(pn);

        Ok(())
    }
}

#[derive(Clone)]
pub struct ClosingSpace {
    ccf_packet: bytes::Bytes,
    rcvd_journal: journal::ArcRcvdJournal,
    keys: Option<(keys::HeaderProtectionKeys, keys::ArcOneRttPacketKeys)>,
    event_broker: event::EventBroker,
}

impl Space {
    pub fn close(self, ccf_packet: bytes::Bytes, event_broker: event::EventBroker) -> ClosingSpace {
        let keys = self.one_rtt_keys.invalid();
        ClosingSpace {
            ccf_packet,
            rcvd_journal: self.journal.of_rcvd_packets(),
            keys,
            event_broker,
        }
    }
}

impl ClosingSpace {
    pub fn ccf_packet(&self) -> bytes::Bytes {
        self.ccf_packet.clone()
    }
}

impl subscribe::Subscribe<OneRttPacket> for ClosingSpace {
    type Error = Infallible;

    fn deliver(&self, (hdr, pkt, offset): OneRttPacket) -> Result<(), Self::Error> {
        let Some(keys) = self.keys.as_ref() else {
            return Ok(());
        };
        let (hpk, pk) = (keys.0.remote.as_ref(), &keys.1);
        let parsed =
            super::util::parse_short_header_packet(pkt, offset, hpk, pk, &self.rcvd_journal);
        let Some((_pn, body_buf)) = parsed else {
            return Ok(());
        };

        let ccf = FrameReader::new(body_buf, hdr.get_type())
            .filter_map(Result::ok)
            .find_map(|(frame, _)| match frame {
                Frame::Close(ccf) => Some(ccf),
                _ => None,
            });
        if let Some(ccf) = ccf {
            _ = self
                .event_broker
                .deliver(event::ConnEvent::ReceivedCcf(ccf));
        }

        Ok(())
    }
}
