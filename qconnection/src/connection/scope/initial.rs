use futures::{channel::mpsc, StreamExt};
use qbase::{
    frame::{AckFrame, DataFrame, Frame, FrameReader},
    packet::{header::GetType, keys::ArcKeys},
};
use qrecovery::{
    space::{Epoch, InitialSpace},
    streams::crypto::CryptoStream,
};

use crate::{
    connection::{decode_long_header_packet, InitialPacketEntry, RcvdInitialPacket},
    error::ConnError,
    path::ArcPath,
    pipe,
};

pub struct InitialScope {
    pub keys: ArcKeys,
    pub space: InitialSpace,
    pub crypto_stream: CryptoStream,
    pub packets_entry: InitialPacketEntry,
}

impl InitialScope {
    // Initial keys应该是预先知道的，或者传入dcid，可以构造出来
    pub fn new(keys: ArcKeys, packets_entry: InitialPacketEntry) -> Self {
        let space = InitialSpace::with_capacity(16);
        let crypto_stream = CryptoStream::new(0, 0);

        Self {
            keys,
            space,
            crypto_stream,
            packets_entry,
        }
    }

    pub fn build(&self, rcvd_packets: RcvdInitialPacket, conn_error: ConnError) {
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();

        let dispatch_frame = move |frame: Frame, path: &ArcPath| {
            match frame {
                Frame::Ack(ack_frame) => {
                    path.on_ack(Epoch::Initial, &ack_frame);
                    _ = ack_frames_entry.unbounded_send(ack_frame);
                }
                Frame::Data(DataFrame::Crypto(crypto), bytes) => {
                    _ = crypto_frames_entry.unbounded_send((crypto, bytes));
                }
                Frame::Close(_) => { /* trustless */ }
                Frame::Padding(_) | Frame::Ping(_) => {}
                _ => unreachable!("unexpected frame: {:?} in initial packet", frame),
            }
        };
        let on_ack = {
            let crypto_stream_outgoing = self.crypto_stream.outgoing();
            let sent_pkt_records = self.space.sent_packets();
            move |ack_frame: &AckFrame| {
                let mut recv_guard = sent_pkt_records.receive();
                recv_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in recv_guard.on_pkt_acked(pn) {
                        crypto_stream_outgoing.on_data_acked(&frame);
                    }
                }
            }
        };

        pipe!(rcvd_crypto_frames |> self.crypto_stream.incoming(), recv_crypto_frame);
        pipe!(rcvd_ack_frames |> on_ack);
        self.parse_rcvd_packets_and_dispatch_frames(rcvd_packets, dispatch_frame, conn_error);
    }

    fn parse_rcvd_packets_and_dispatch_frames(
        &self,
        mut rcvd_packets: RcvdInitialPacket,
        dispatch_frame: impl Fn(Frame, &ArcPath) + Send + 'static,
        conn_error: ConnError,
    ) {
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.keys.clone();
            async move {
                while let Some((packet, path)) = rcvd_packets.next().await {
                    let pty = packet.header.get_type();
                    let decode_pn = |pn| rcvd_pkt_records.decode_pn(pn).ok();
                    let (pn, payload) =
                        match decode_long_header_packet(packet, &keys, decode_pn).await {
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
                            path.on_recv_pkt(Epoch::Initial, pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });
    }
}
