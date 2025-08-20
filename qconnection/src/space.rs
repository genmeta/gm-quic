pub mod data;
pub mod handshake;
pub mod initial;

use std::{fmt::Debug, sync::Arc};

use bytes::Bytes;
use qbase::{
    error::Error,
    frame::{
        AckFrame, ConnectionCloseFrame, CryptoFrame, FrameFeature, GetFrameType, ReceiveFrame,
        ReliableFrame, StreamCtlFrame, StreamFrame,
    },
    packet::{
        AssemblePacket, Package, PacketSpace, PacketWriter, ProductHeader,
        header::short::OneRttHeader,
        io::{Packages, PadTo20},
    },
};
use qevent::{quic::transport::PacketsAcked, telemetry::Instrument};
use qinterface::queue::RcvdPacketQueue;
use qrecovery::{
    crypto::{CryptoStream, CryptoStreamOutgoing},
    journal::{ArcSentJournal, Journal},
};
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::Instrument as _;

use crate::{
    Components, DataStreams, FlowController, GuaranteedFrame,
    events::{ArcEventBroker, EmitEvent, Event},
    termination::Terminator,
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
}

fn assemble_closing_packet<'s, 'b: 's, H, S>(
    space: &'s S,
    product_header: &impl ProductHeader<H>,
    buffer: &'b mut [u8],
    ccf: &ConnectionCloseFrame,
) -> Option<usize>
where
    S: PacketSpace<H>,
    S::PacketAssembler<'s>: AsRef<PacketWriter<'b>>,
    for<'f> &'f ConnectionCloseFrame: Package<S::PacketAssembler<'s>>,
{
    let header = product_header.new_header().ok()?;
    let mut packet = S::new_packet(space, header, buffer).ok()?;
    if !ccf.belongs_to(packet.as_ref().packet_type()) {
        let ccf = ConnectionCloseFrame::from(match ccf {
            ConnectionCloseFrame::App(app_close_frame) => app_close_frame.conceal(),
            ConnectionCloseFrame::Quic(..) => unreachable!(),
        });
        packet
            .assemble_packet(&mut Packages((&ccf, PadTo20)))
            .ok()?;
    } else {
        packet.assemble_packet(&mut Packages((ccf, PadTo20))).ok()?;
    }
    Some(packet.encrypt_and_protect_packet().0)
}

impl Spaces {
    pub async fn close(
        self,
        terminator: Arc<Terminator>,
        rcvd_pkt_q: Arc<RcvdPacketQueue>,
        event_broker: ArcEventBroker,
    ) {
        _ = terminator
            .try_send(|buf, ccf| {
                assemble_closing_packet(self.initial().as_ref(), terminator.as_ref(), buf, ccf)
            })
            .await;
        initial::spawn_deliver_and_parse_closing(
            rcvd_pkt_q.initial().clone(),
            self.initial.clone(),
            terminator.clone(),
            event_broker.clone(),
        );

        rcvd_pkt_q.zero_rtt().close();

        _ = terminator
            .try_send(|buf, ccf| {
                assemble_closing_packet(self.handshake().as_ref(), terminator.as_ref(), buf, ccf)
            })
            .await;
        handshake::spawn_deliver_and_parse_closing(
            rcvd_pkt_q.handshake().clone(),
            self.handshake.clone(),
            terminator.clone(),
            event_broker.clone(),
        );

        _ = terminator
            .try_send(|buf, ccf| {
                let space = self.data().as_ref();
                assemble_closing_packet::<OneRttHeader, _>(space, terminator.as_ref(), buf, ccf)
            })
            .await;
        data::spawn_deliver_and_parse_closing(
            rcvd_pkt_q.one_rtt().clone(),
            self.data.clone(),
            terminator.clone(),
            event_broker.clone(),
        );
    }

    pub async fn drain(self, terminator: Arc<Terminator>, rcvd_pkt_q: Arc<RcvdPacketQueue>) {
        rcvd_pkt_q.close_all();
        // For the client, this may cause the server to establish a new connection state and then quickly end it.
        // (especially when the pto is very small, such as a loopback NIC).
        _ = terminator
            .try_send(|buf, ccf| {
                assemble_closing_packet(self.initial().as_ref(), terminator.as_ref(), buf, ccf)
            })
            .await;
        _ = terminator
            .try_send(|buf, ccf| {
                assemble_closing_packet(self.handshake().as_ref(), terminator.as_ref(), buf, ccf)
            })
            .await;
        _ = terminator
            .try_send(|buf, ccf| {
                let space = self.data().as_ref();
                assemble_closing_packet::<OneRttHeader, _>(space, terminator.as_ref(), buf, ccf)
            })
            .await;
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
                if let Err(Error::Quic(e)) = destination.recv_frame(&f) {
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
            Err(e) => {
                tracing::error!("   Cause by: received an invalid StreamFrame");
                return Err(e.into());
            }
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
            Err(e) => {
                tracing::error!("   Cause by: received an invalid StreamCtlFrame");
                return Err(e.into());
            }
        }
        Ok(())
    }
}

struct AckInitialSpace {
    sent_journal: ArcSentJournal<CryptoFrame>,
    crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl AckInitialSpace {
    fn new(journal: &Journal<CryptoFrame>, crypto_stream: &CryptoStream) -> Self {
        Self {
            sent_journal: journal.of_sent_packets(),
            crypto_stream_outgoing: crypto_stream.outgoing(),
        }
    }
}

impl ReceiveFrame<AckFrame> for AckInitialSpace {
    type Output = ();

    fn recv_frame(&self, ack_frame: &AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.sent_journal.rotate();
        rotate_guard.update_largest(ack_frame)?;

        let acked = ack_frame.iter().flat_map(|r| r.rev()).collect::<Vec<_>>();
        qevent::event!(PacketsAcked {
            packet_number_space: qbase::Epoch::Initial,
            packet_nubers: acked.clone(),
        });
        for pn in acked {
            for frame in rotate_guard.on_packet_acked(pn) {
                self.crypto_stream_outgoing.on_data_acked(&frame);
            }
        }

        Ok(())
    }
}

struct AckHandshakeSpace {
    sent_journal: ArcSentJournal<CryptoFrame>,
    crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl AckHandshakeSpace {
    fn new(journal: &Journal<CryptoFrame>, crypto_stream: &CryptoStream) -> Self {
        Self {
            sent_journal: journal.of_sent_packets(),
            crypto_stream_outgoing: crypto_stream.outgoing(),
        }
    }
}

impl ReceiveFrame<AckFrame> for AckHandshakeSpace {
    type Output = ();

    fn recv_frame(&self, ack_frame: &AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.sent_journal.rotate();
        rotate_guard.update_largest(ack_frame)?;

        let acked = ack_frame.iter().flat_map(|r| r.rev()).collect::<Vec<_>>();
        qevent::event!(PacketsAcked {
            packet_number_space: qbase::Epoch::Handshake,
            packet_nubers: acked.clone(),
        });
        for pn in acked {
            for frame in rotate_guard.on_packet_acked(pn) {
                self.crypto_stream_outgoing.on_data_acked(&frame);
            }
        }

        Ok(())
    }
}

struct AckDataSpace {
    send_journal: ArcSentJournal<GuaranteedFrame>,
    data_streams: DataStreams,
    crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl AckDataSpace {
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

impl ReceiveFrame<AckFrame> for AckDataSpace {
    type Output = ();

    fn recv_frame(&self, ack_frame: &AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.send_journal.rotate();
        rotate_guard.update_largest(ack_frame)?;

        let acked = ack_frame.iter().flat_map(|r| r.rev()).collect::<Vec<_>>();
        qevent::event!(PacketsAcked {
            packet_number_space: qbase::Epoch::Data,
            packet_nubers: acked.clone(),
        });
        for pn in acked {
            for frame in rotate_guard.on_packet_acked(pn) {
                match frame {
                    GuaranteedFrame::Stream(stream_frame) => {
                        self.data_streams.on_data_acked(stream_frame)
                    }
                    GuaranteedFrame::Crypto(crypto_frame) => {
                        self.crypto_stream_outgoing.on_data_acked(&crypto_frame)
                    }
                    GuaranteedFrame::Reliable(ReliableFrame::StreamCtl(
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
        received_packets_queue.initial().clone(),
        components.spaces.initial.clone(),
        components,
        components.event_broker.clone(),
    );
    handshake::spawn_deliver_and_parse(
        received_packets_queue.handshake().clone(),
        components.spaces.handshake.clone(),
        components,
        components.event_broker.clone(),
    );
    data::spawn_deliver_and_parse(
        received_packets_queue.zero_rtt().clone(),
        received_packets_queue.one_rtt().clone(),
        components.spaces.data.clone(),
        components,
        components.event_broker.clone(),
    );
}
