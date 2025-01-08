pub mod data;
pub mod handshake;
pub mod initial;

use std::future::Future;

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
    DataStreams, FlowController,
};

#[derive(Clone)]
pub struct Spaces {
    pub initial: initial::InitialSpace,
    pub handshake: handshake::HandshakeSpace,
    pub data: data::DataSpace,
}

pub struct DecryptedPacket<H> {
    header: H,
    pn: u64,
    payload: Bytes,
}

async fn try_join2<T1, T2>(
    f1: impl Future<Output = Option<T1>> + Unpin,
    f2: impl Future<Output = Option<T2>> + Unpin,
) -> Option<(T1, T2)> {
    use futures::future::*;
    match select(f1, f2).await {
        Either::Left((None, ..)) => None,
        Either::Right((None, ..)) => None,
        Either::Left((Some(t1), f2)) => Some((t1, f2.await?)),
        Either::Right((Some(t2), f1)) => Some((f1.await?, t2)),
    }
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
