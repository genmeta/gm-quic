pub mod data;
pub mod handshake;
pub mod initial;

use std::{fmt::Debug, sync::Arc};

use bytes::{Bytes, BytesMut};
use qbase::{
    error::Error,
    frame::{
        AckFrame, BeFrame, CryptoFrame, ReceiveFrame, ReliableFrame, StreamCtlFrame, StreamFrame,
    },
    packet::{
        decrypt::{
            decrypt_packet, remove_protection_of_long_packet, remove_protection_of_short_packet,
        },
        keys::ArcOneRttPacketKeys,
        number::PacketNumber,
    },
};
use qlog::{
    quic::{
        PacketHeader, PacketHeaderBuilder, QuicFrame,
        transport::{PacketDropped, PacketDroppedTrigger, PacketReceived, PacketsAcked},
    },
    telemetry::Instrument,
};
use qrecovery::{
    crypto::{CryptoStream, CryptoStreamOutgoing},
    journal::{ArcSentJournal, InvalidPacketNumber, Journal},
    reliable::GuaranteedFrame,
};
use rustls::quic::{HeaderProtectionKey, PacketKey};
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::Instrument as _;

use crate::{
    Components, DataStreams, FlowController,
    events::{ArcEventBroker, EmitEvent, Event},
    termination::ClosingState,
};

#[derive(Clone)]
pub struct Spaces {
    initial: Arc<initial::InitialSpace>,
    handshake: Arc<handshake::HandshakeSpace>,
    data: Arc<data::DataSpace>,
}

impl Spaces {
    pub fn new(
        initial: initial::InitialSpace,
        handshake: handshake::HandshakeSpace,
        data: data::DataSpace,
    ) -> Self {
        Self {
            initial: Arc::new(initial),
            handshake: Arc::new(handshake),
            data: Arc::new(data),
        }
    }

    pub fn initial(&self) -> &Arc<initial::InitialSpace> {
        &self.initial
    }

    pub fn handshake(&self) -> &Arc<handshake::HandshakeSpace> {
        &self.handshake
    }

    pub fn data(&self) -> &Arc<data::DataSpace> {
        &self.data
    }

    pub fn close(self, closing_state: Arc<ClosingState>, event_broker: ArcEventBroker) {
        let received_packet_queue = closing_state.rcvd_pkt_q();
        match self.initial.close() {
            None => received_packet_queue.initial().close(),
            Some(space) => {
                initial::spawn_deliver_and_parse_closing(
                    received_packet_queue.initial().receiver(),
                    space,
                    closing_state.clone(),
                    event_broker.clone(),
                );
            }
        }

        received_packet_queue.zero_rtt().close();

        match self.handshake.close() {
            None => received_packet_queue.handshake().close(),
            Some(space) => {
                handshake::spawn_deliver_and_parse_closing(
                    received_packet_queue.handshake().receiver(),
                    space,
                    closing_state.clone(),
                    event_broker.clone(),
                );
            }
        }

        match self.data.close() {
            None => received_packet_queue.one_rtt().close(),
            Some(space) => {
                data::spawn_deliver_and_parse_closing(
                    received_packet_queue.one_rtt().receiver(),
                    space,
                    closing_state.clone(),
                    event_broker.clone(),
                );
            }
        }
    }
}

pub struct ReceivedCipherPacket<H> {
    header: H,
    payload: BytesMut,
    payload_offset: usize,
}

impl<H> From<(H, BytesMut, usize)> for ReceivedCipherPacket<H> {
    fn from((header, payload, payload_offset): (H, BytesMut, usize)) -> Self {
        Self {
            header,
            payload,
            payload_offset,
        }
    }
}

impl<H> ReceivedCipherPacket<H>
where
    PacketHeaderBuilder: for<'a> From<&'a H>,
{
    fn qlog_header(&self) -> PacketHeader {
        PacketHeaderBuilder::from(&self.header).build()
    }

    fn drop_on_key_unavailable(self) {
        qlog::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.payload.freeze(),
            trigger: PacketDroppedTrigger::KeyUnavailable
        })
    }

    fn drop_on_remove_header_protection_failure(self) {
        qlog::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.payload.freeze(),
            details: Map {
                reason: "remove header protection failure",
            },
            trigger: PacketDroppedTrigger::DecryptionFailure
        })
    }

    fn drop_on_decryption_failure(self, error: qbase::packet::error::Error, pn: u64) {
        qlog::event!(PacketDropped {
            header: {
                PacketHeaderBuilder::from(&self.header)
                    .packet_number(pn)
                    .build()
            },
            raw: self.payload.freeze(),
            details: Map {
                reason: "decryption failure",
                error: error.to_string(),
            },
            trigger: PacketDroppedTrigger::DecryptionFailure
        })
    }

    fn drop_on_reverse_bit_error(self, error: &qbase::packet::error::Error) {
        qlog::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.payload.freeze(),
            details: Map {
                reason: "reverse bit error",
                error: error.to_string()
            },
            trigger: PacketDroppedTrigger::Invalid,
        })
    }

    fn drop_on_invalid_pn(self, invalid_pn: qrecovery::journal::InvalidPacketNumber) {
        qlog::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.payload.freeze(),
            details: Map {
                reason: "invalid packet number",
                invalid_pn: invalid_pn.to_string()
            },
            trigger: PacketDroppedTrigger::Invalid,
        })
    }

    fn decrypt_as_long(
        mut self,
        hpk: &dyn HeaderProtectionKey,
        pk: &dyn PacketKey,
        pn_decoder: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
    ) -> Option<Result<PlainPacket<H>, Error>> {
        let pkt_buf = self.payload.as_mut();
        let undecoded_pn = match remove_protection_of_long_packet(hpk, pkt_buf, self.payload_offset)
        {
            Ok(Some(undecoded_pn)) => undecoded_pn,
            Ok(None) => {
                self.drop_on_remove_header_protection_failure();
                return None;
            }
            Err(invalid_reverse_bits) => {
                self.drop_on_reverse_bit_error(&invalid_reverse_bits);
                return Some(Err(invalid_reverse_bits.into()));
            }
        };
        let decoded_pn = match pn_decoder(undecoded_pn) {
            Ok(pn) => pn,
            Err(invalid_pn) => {
                self.drop_on_invalid_pn(invalid_pn);
                return None;
            }
        };
        let body_offset = self.payload_offset + undecoded_pn.size();
        let body_length = match decrypt_packet(pk, decoded_pn, pkt_buf, body_offset) {
            Ok(body_length) => body_length,
            Err(error) => {
                self.drop_on_decryption_failure(error, decoded_pn);
                return None;
            }
        };

        Some(Ok(PlainPacket {
            header: self.header,
            plain: self.payload.freeze(),
            payload_offset: self.payload_offset,
            undecoded_pn,
            decoded_pn,
            body_length,
        }))
    }

    fn decrypt_as_short(
        mut self,
        hpk: &dyn HeaderProtectionKey,
        pk: &ArcOneRttPacketKeys,
        pn_decoder: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
    ) -> Option<Result<PlainPacket<H>, Error>> {
        let pkt_buf = self.payload.as_mut();
        let (undecoded_pn, key_phase) =
            match remove_protection_of_short_packet(hpk, pkt_buf, self.payload_offset) {
                Ok(Some((undecoded, key_phase))) => (undecoded, key_phase),
                Ok(None) => {
                    self.drop_on_remove_header_protection_failure();
                    return None;
                }
                Err(invalid_reverse_bits) => {
                    self.drop_on_reverse_bit_error(&invalid_reverse_bits);
                    return Some(Err(invalid_reverse_bits.into()));
                }
            };
        let decoded_pn = match pn_decoder(undecoded_pn) {
            Ok(pn) => pn,
            Err(invalid_pn) => {
                self.drop_on_invalid_pn(invalid_pn);
                return None;
            }
        };
        let pk = pk.lock_guard().get_remote(key_phase, decoded_pn);
        let body_offset = self.payload_offset + undecoded_pn.size();
        let body_length = match decrypt_packet(pk.as_ref(), decoded_pn, pkt_buf, body_offset) {
            Ok(body_length) => body_length,
            Err(error) => {
                self.drop_on_decryption_failure(error, decoded_pn);
                return None;
            }
        };

        Some(Ok(PlainPacket {
            header: self.header,
            plain: self.payload.freeze(),
            payload_offset: self.payload_offset,
            undecoded_pn,
            decoded_pn,
            body_length,
        }))
    }
}

impl initial::ReceivedInitialPacket {
    pub fn drop_on_scid_unmatch(self) {
        qlog::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.payload.freeze(),
            details: Map {
                reason: "different scid with first initial packet"
            },
            trigger: PacketDroppedTrigger::Rejected
        })
    }
}

pub struct PlainPacket<H> {
    header: H,
    decoded_pn: u64,
    undecoded_pn: PacketNumber,
    plain: Bytes,
    payload_offset: usize,
    body_length: usize,
}

impl<H> PlainPacket<H> {
    pub fn payload_length(&self) -> usize {
        self.undecoded_pn.size() + self.body_length
    }

    pub fn body(&self) -> Bytes {
        let packet_offset = self.payload_offset + self.undecoded_pn.size();
        self.plain
            .slice(packet_offset..packet_offset + self.body_length)
    }

    pub fn raw_info(&self) -> qlog::RawInfo {
        qlog::build!(qlog::RawInfo {
            length: self.plain.len() as u64,
            payload_length: self.payload_length() as u64,
            data: &self.plain,
        })
    }
}

impl<H> PlainPacket<H>
where
    PacketHeaderBuilder: for<'a> From<&'a H>,
{
    pub fn qlog_header(&self) -> PacketHeader {
        let mut builder = PacketHeaderBuilder::from(&self.header);
        qlog::build! {@field builder,
            packet_number: self.decoded_pn,
            length: self.payload_length() as u16
        };
        builder.build()
    }

    pub fn drop_on_conenction_closed(self) {
        qlog::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.raw_info(),
            details: Map {
                reason: "connection closed"
            },
            trigger: PacketDroppedTrigger::Genera
        })
    }

    pub fn emit_received(&self, frames: impl Into<Vec<QuicFrame>>) {
        qlog::event!(PacketReceived {
            header: self.qlog_header(),
            frames,
            raw: self.raw_info(),
        })
    }
}

fn pipe<F: Send + Debug + 'static>(
    mut source: UnboundedReceiver<F>,
    destination: impl ReceiveFrame<F> + Send + 'static,
    broker: ArcEventBroker,
) {
    tokio::spawn(
        async move {
            while let Some(f) = source.recv().await {
                if let Err(e) = destination.recv_frame(&f) {
                    broker.emit(Event::Failed(e));
                    break;
                }
            }
        }
        .instrument_in_current()
        .in_current_span(),
    );
}

/// When receiving a [`StreamFrame`] or [`StreamCtlFrame`],
/// flow control must be updated accordingly
#[derive(Clone)]
struct FlowControlledDataStreams {
    streams: DataStreams,
    flow_ctrl: FlowController,
}

impl FlowControlledDataStreams {
    fn new(streams: DataStreams, flow_ctrl: FlowController) -> Self {
        Self { streams, flow_ctrl }
    }
}

impl ReceiveFrame<(StreamFrame, Bytes)> for FlowControlledDataStreams {
    type Output = ();

    fn recv_frame(&self, data_frame: &(StreamFrame, Bytes)) -> Result<Self::Output, Error> {
        match self.streams.recv_data(data_frame) {
            Ok(new_data_size) => {
                self.flow_ctrl
                    .on_new_rcvd(data_frame.0.frame_type(), new_data_size)?;
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }
}

impl ReceiveFrame<StreamCtlFrame> for FlowControlledDataStreams {
    type Output = ();

    fn recv_frame(&self, frame: &StreamCtlFrame) -> Result<Self::Output, Error> {
        match self.streams.recv_stream_control(frame) {
            Ok(new_data_size) => {
                self.flow_ctrl
                    .on_new_rcvd(frame.frame_type(), new_data_size)?;
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }
}

struct AckInitial {
    sent_journal: ArcSentJournal<CryptoFrame>,
    crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl AckInitial {
    fn new(journal: &Journal<CryptoFrame>, crypto_stream: &CryptoStream) -> Self {
        Self {
            sent_journal: journal.of_sent_packets(),
            crypto_stream_outgoing: crypto_stream.outgoing(),
        }
    }
}

impl ReceiveFrame<AckFrame> for AckInitial {
    type Output = ();

    fn recv_frame(&self, ack_frame: &AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.sent_journal.rotate();
        rotate_guard.update_largest(ack_frame)?;

        let acked = ack_frame.iter().flat_map(|r| r.rev()).collect::<Vec<_>>();
        qlog::event!(PacketsAcked {
            packet_number_space: qbase::Epoch::Initial,
            packet_nubers: acked.clone(),
        });
        for pn in acked {
            for frame in rotate_guard.on_pkt_acked(pn) {
                self.crypto_stream_outgoing.on_data_acked(&frame);
            }
        }

        Ok(())
    }
}

struct AckHandshake {
    sent_journal: ArcSentJournal<CryptoFrame>,
    crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl AckHandshake {
    fn new(journal: &Journal<CryptoFrame>, crypto_stream: &CryptoStream) -> Self {
        Self {
            sent_journal: journal.of_sent_packets(),
            crypto_stream_outgoing: crypto_stream.outgoing(),
        }
    }
}

impl ReceiveFrame<AckFrame> for AckHandshake {
    type Output = ();

    fn recv_frame(&self, ack_frame: &AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.sent_journal.rotate();
        rotate_guard.update_largest(ack_frame)?;

        let acked = ack_frame.iter().flat_map(|r| r.rev()).collect::<Vec<_>>();
        qlog::event!(PacketsAcked {
            packet_number_space: qbase::Epoch::Handshake,
            packet_nubers: acked.clone(),
        });
        for pn in acked {
            for frame in rotate_guard.on_pkt_acked(pn) {
                self.crypto_stream_outgoing.on_data_acked(&frame);
            }
        }

        Ok(())
    }
}

struct AckData {
    send_journal: ArcSentJournal<GuaranteedFrame>,
    data_streams: DataStreams,
    crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl AckData {
    fn new(
        journal: &Journal<GuaranteedFrame>,
        data_streams: &DataStreams,
        crypto_stream: &CryptoStream,
    ) -> Self {
        Self {
            send_journal: journal.of_sent_packets(),
            data_streams: data_streams.clone(),
            crypto_stream_outgoing: crypto_stream.outgoing(),
        }
    }
}

impl ReceiveFrame<AckFrame> for AckData {
    type Output = ();

    fn recv_frame(&self, ack_frame: &AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.send_journal.rotate();
        rotate_guard.update_largest(ack_frame)?;

        let acked = ack_frame.iter().flat_map(|r| r.rev()).collect::<Vec<_>>();
        qlog::event!(PacketsAcked {
            packet_number_space: qbase::Epoch::Data,
            packet_nubers: acked.clone(),
        });
        for pn in acked {
            for frame in rotate_guard.on_pkt_acked(pn) {
                match frame {
                    GuaranteedFrame::Stream(stream_frame) => {
                        self.data_streams.on_data_acked(stream_frame)
                    }
                    GuaranteedFrame::Crypto(crypto_frame) => {
                        self.crypto_stream_outgoing.on_data_acked(&crypto_frame)
                    }
                    GuaranteedFrame::Reliable(ReliableFrame::Stream(
                        StreamCtlFrame::ResetStream(reset_frame),
                    )) => self.data_streams.on_reset_acked(reset_frame),
                    _ => { /* nothing to do */ }
                }
            }
        }
        Ok(())
    }
}

pub fn spawn_deliver_and_parse(components: &Components) {
    let received_packets_queue = &components.rcvd_pkt_q;
    initial::spawn_deliver_and_parse(
        received_packets_queue.initial().receiver(),
        components.spaces.initial.clone(),
        components,
        components.event_broker.clone(),
    );
    handshake::spawn_deliver_and_parse(
        received_packets_queue.handshake().receiver(),
        components.spaces.handshake.clone(),
        components,
        components.event_broker.clone(),
    );
    data::spawn_deliver_and_parse(
        received_packets_queue.zero_rtt().receiver(),
        received_packets_queue.one_rtt().receiver(),
        components.spaces.data.clone(),
        components,
        components.event_broker.clone(),
    );
}
