pub mod data;
pub mod handshake;
pub mod initial;

use std::sync::Arc;

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

use crate::{
    events::{EmitEvent, Event},
    ArcClosingInterface, Components, DataStreams, FlowController,
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

    pub fn initial(&self) -> &initial::InitialSpace {
        &self.initial
    }

    pub fn handshake(&self) -> &handshake::HandshakeSpace {
        &self.handshake
    }

    pub fn data(&self) -> &data::DataSpace {
        &self.data
    }

    pub fn close<EE>(self, closing_iface: ArcClosingInterface, event_broker: &EE)
    where
        EE: EmitEvent + Clone + Send + 'static,
    {
        let received_packets_buffer = closing_iface.received_packets_buffer();
        match self.initial.close() {
            None => received_packets_buffer.initial().close(),
            Some(space) => {
                initial::launch_deliver_and_parse_closing(
                    received_packets_buffer.initial().receiver(),
                    space,
                    closing_iface.clone(),
                    event_broker.clone(),
                );
            }
        }

        received_packets_buffer.zero_rtt().close();

        match self.handshake.close() {
            None => received_packets_buffer.handshake().close(),
            Some(space) => {
                handshake::launch_deliver_and_parse_closing(
                    received_packets_buffer.handshake().receiver(),
                    space,
                    closing_iface.clone(),
                    event_broker.clone(),
                );
            }
        }

        match self.data.close() {
            None => received_packets_buffer.one_rtt().close(),
            Some(space) => {
                data::launch_deliver_and_parse_closing(
                    received_packets_buffer.one_rtt().receiver(),
                    space,
                    closing_iface.clone(),
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

fn pipe<F: Send + 'static>(
    mut source: UnboundedReceiver<F>,
    destination: impl ReceiveFrame<F> + Send + 'static,
    broker: impl EmitEvent + Send + 'static,
) {
    tokio::spawn(async move {
        while let Some(f) = source.recv().await {
            if let Err(e) = destination.recv_frame(&f) {
                broker.emit(Event::Failed(e));
                break;
            }
        }
    });
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

    fn recv_frame(&self, ack_frame: &AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.sent_journal.rotate();
        rotate_guard.update_largest(ack_frame.largest.into_inner());

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

    fn recv_frame(&self, ack_frame: &AckFrame) -> Result<Self::Output, Error> {
        let mut rotate_guard = self.send_journal.rotate();
        rotate_guard.update_largest(ack_frame.largest.into_inner());

        for pn in ack_frame.iter().flat_map(|r| r.rev()) {
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

pub fn launch_deliver_and_parse<EE>(components: &Components, event_broker: EE)
where
    EE: EmitEvent + Clone + Send + Sync + 'static,
{
    let received_packets_buffer = components.conn_iface.received_packets_buffer();
    initial::launch_deliver_and_parse(
        received_packets_buffer.initial().receiver(),
        components.spaces.initial.clone(),
        components,
        event_broker.clone(),
    );
    handshake::launch_deliver_and_parse(
        received_packets_buffer.handshake().receiver(),
        components.spaces.handshake.clone(),
        components,
        event_broker.clone(),
    );
    data::launch_deliver_and_parse(
        received_packets_buffer.zero_rtt().receiver(),
        received_packets_buffer.one_rtt().receiver(),
        components.spaces.data.clone(),
        components,
        event_broker,
    );
}
