pub mod data;
pub mod handshake;
pub mod initial;

use std::{fmt::Debug, sync::Arc};

use bytes::Bytes;
use qbase::{
    error::Error,
    frame::{
        AckFrame, BeFrame, CryptoFrame, ReceiveFrame, ReliableFrame, StreamCtlFrame, StreamFrame,
    },
};
use qrecovery::{
    crypto::{CryptoStream, CryptoStreamOutgoing},
    journal::{ArcSentJournal, Journal},
    reliable::GuaranteedFrame,
};
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{trace_span, Instrument};

use crate::{
    events::{ArcEventBroker, EmitEvent, Event},
    termination::ClosingState,
    Components, DataStreams, FlowController,
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

pub struct DecryptedPacket<H> {
    header: H,
    pn: u64,
    payload: Bytes,
}

fn pipe<F: Send + Debug + 'static>(
    mut source: UnboundedReceiver<F>,
    destination: impl ReceiveFrame<F> + Send + 'static,
    broker: ArcEventBroker,
) {
    tokio::spawn(
        async move {
            while let Some(f) = source.recv().await {
                tracing::trace!(frame = ?f, "received frame");
                if let Err(e) = destination.recv_frame(&f) {
                    broker.emit(Event::Failed(e));
                    break;
                }
            }
            tracing::trace!(frame_type = core::any::type_name::<F>(), "pipeline broken");
        }
        .instrument(trace_span!("frame_pipeline",)),
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

type AckInitial = AckHandshake;

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

    #[tracing::instrument(name = "recv_ack_frame", level = "trace", skip(self), ret, err)]
    fn recv_frame(&self, ack_frame: &AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.sent_journal.rotate();
        rotate_guard.update_largest(ack_frame)?;

        for pn in ack_frame.iter().flat_map(|r| r.rev()) {
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

    #[tracing::instrument(name = "recv_ack_frame", level = "trace", skip(self), ret, err)]
    fn recv_frame(&self, ack_frame: &AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.send_journal.rotate();
        rotate_guard.update_largest(ack_frame)?;

        for pn in ack_frame.iter().flat_map(|r| r.rev()) {
            tracing::trace!(?pn, "packet acked");
            for frame in rotate_guard.on_pkt_acked(pn) {
                tracing::trace!(?frame, "frame acked");
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
