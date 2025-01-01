pub mod data;
pub mod handshake;
pub mod initial;

use std::future::Future;

use bytes::Bytes;
pub use data::{ClosingOneRttScope, DataSpace};
use futures::{channel::mpsc::UnboundedReceiver, StreamExt};
pub use handshake::{ClosingHandshakeScope, HandshakeSpace};
pub use initial::InitialSpace;
use qbase::{
    error::Error,
    frame::{
        AckFrame, BeFrame, CryptoFrame, Frame, FrameReader, ReceiveFrame, ReliableFrame,
        StreamCtlFrame, StreamFrame,
    },
    packet::{decrypt::decrypt_packet, header::GetType, DataPacket},
};
use qrecovery::{
    crypto::{CryptoStream, CryptoStreamOutgoing},
    journal::{ArcSentJournal, Journal},
    reliable::GuaranteedFrame,
};
use tokio::sync::Notify;

use crate::{
    events::{EmitEvent, Event},
    DataStreams, FlowController,
};

pub trait RecvPacket {
    fn has_rcvd_ccf(&self, packet: DataPacket) -> bool;

    fn decrypt_and_parse(
        key: &dyn rustls::quic::PacketKey,
        pn: u64,
        mut packet: DataPacket,
        body_offset: usize,
    ) -> bool {
        decrypt_packet(key, pn, packet.bytes.as_mut(), body_offset).unwrap();
        let body = packet.bytes.split_off(body_offset);
        FrameReader::new(body.freeze(), packet.header.get_type())
            .filter_map(|frame| frame.ok())
            .any(|(f, _)| matches!(f, Frame::Close(_)))
    }
}

async fn any<F, T>(fut: F, notify: &Notify) -> Option<T>
where
    F: Future<Output = Option<T>>,
{
    tokio::select! {
        _ = notify.notified() => None,
        v = fut => v,
    }
}

fn pipe<F: Send + 'static>(
    mut source: UnboundedReceiver<F>,
    destination: impl ReceiveFrame<F, Output = ()> + Send + 'static,
    broker: impl EmitEvent + Send + 'static,
) {
    tokio::spawn(async move {
        while let Some(f) = source.next().await {
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
