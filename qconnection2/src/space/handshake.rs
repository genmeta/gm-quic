use std::sync::Arc;

use bytes::BufMut as _;
use qbase::{
    frame::{CryptoFrame, Frame, FrameReader, ReceiveFrame as _},
    packet::{
        self,
        header::{long::HandshakeHeader, GetType as _},
        keys,
    },
};
use qcongestion::CongestionControl as _;
use qrecovery::{crypto, journal};

use crate::{event, path, tx, util::subscribe};

#[derive(Clone)]
pub struct Space {
    keys: keys::ArcKeys,
    journal: journal::HandshakeJournal,
    crypto_stream: crypto::CryptoStream,
}

impl Default for Space {
    fn default() -> Self {
        Self::new()
    }
}

impl Space {
    pub fn new() -> Self {
        Self {
            keys: keys::ArcKeys::new_pending(),
            journal: journal::InitialJournal::with_capacity(16),
            crypto_stream: crypto::CryptoStream::new(4096, 4096),
        }
    }

    // todo: 暂时只检测密钥
    pub fn has_pending_data(&self) -> bool {
        self.keys.get_local_keys().is_some()
    }

    pub fn try_assemble<'b>(
        &self,
        tx: &mut tx::Transaction<'_>,
        buf: &'b mut [u8],
        fill: bool,
    ) -> Option<(packet::AssembledPacket<'b>, Option<u64>)> {
        let keys = self.keys.get_local_keys()?;
        let sent_journal = self.journal.of_sent_packets();
        let mut packet = tx::PacketMemory::new(
            packet::header::LongHeaderBuilder::with_cid(tx.dcid(), tx.scid()).handshake(),
            buf,
            keys.local.packet.tag_len(),
            &sent_journal,
        )?;

        let mut ack = None;
        if let Some((largest, rcvd_time)) = tx.need_ack(qbase::Epoch::Handshake) {
            let rcvd_journal = self.journal.of_rcvd_packets();
            if let Some(ack_frame) =
                rcvd_journal.gen_ack_frame_util(largest, rcvd_time, packet.remaining_mut())
            {
                packet.dump_ack_frame(ack_frame);
                ack = Some(largest);
            }
        }

        // TODO: 可以封装在CryptoStream中，当成一个函数
        //      crypto_stream.try_load_data_into(&mut packet);
        let crypto_stream_outgoing = self.crypto_stream.outgoing();
        crypto_stream_outgoing.try_load_data_into(&mut packet);

        if fill {
            let remaining = packet.remaining_mut();
            packet.put_bytes(0, remaining);
        }

        let packet: packet::PacketWriter<'b> = packet.try_into().ok()?;
        Some((
            packet.encrypt_long_packet(keys.local.header.as_ref(), keys.local.packet.as_ref()),
            ack,
        ))
    }

    pub fn tracker(&self) -> Tracker {
        Tracker {
            journal: self.journal.clone(),
            outgoing: self.crypto_stream.outgoing().clone(),
        }
    }
}

#[derive(Clone)]
pub struct Tracker {
    journal: journal::HandshakeJournal,
    outgoing: crypto::CryptoStreamOutgoing,
}

impl qcongestion::TrackPackets for Tracker {
    fn may_loss(&self, pn: u64) {
        for frame in self.journal.of_sent_packets().rotate().may_loss_pkt(pn) {
            self.outgoing.may_loss_data(&frame);
        }
    }

    fn retire(&self, pn: u64) {
        self.journal.of_rcvd_packets().write().retire(pn);
    }
}

pub struct PacketEntry {
    keys: Arc<rustls::quic::Keys>,
    crypto_stream_incoming: crypto::CryptoStreamIncoming,
    crypto_stream_outgoing: crypto::CryptoStreamOutgoing,
    sent_journal: journal::ArcSentJournal<CryptoFrame>,
    rcvd_journal: journal::ArcRcvdJournal,

    // EventBroker
    event_broker: Arc<event::EventBroker>,
}

impl PacketEntry {
    pub async fn new(space: Space, event_broker: Arc<event::EventBroker>) -> Option<Self> {
        let keys = space.keys.get_remote_keys().await?;
        let crypto_stream_incoming = space.crypto_stream.incoming();
        let crypto_stream_outgoing = space.crypto_stream.outgoing();
        let sent_journal = space.journal.of_sent_packets();
        let rcvd_journal = space.journal.of_rcvd_packets();

        let event_broker = event_broker.clone();

        Some(Self {
            keys,
            crypto_stream_incoming,
            crypto_stream_outgoing,
            sent_journal,
            rcvd_journal,
            event_broker,
        })
    }

    fn dispatch_frame(&self, frame: Frame, path: &path::Path) {
        use subscribe::Subscribe as _;
        match frame {
            Frame::Ack(ack_frame) => {
                path.cc().on_ack(qbase::Epoch::Initial, &ack_frame);
                let mut recv_guard = self.sent_journal.rotate();
                recv_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in recv_guard.on_pkt_acked(pn) {
                        self.crypto_stream_outgoing.on_data_acked(&frame);
                    }
                }
            }
            Frame::Crypto(f, bytes) => _ = self.crypto_stream_incoming.recv_frame(&(f, bytes)),
            Frame::Close(ccf) => {
                _ = self
                    .event_broker
                    .deliver(event::ConnEvent::ReceivedCcf(ccf));
            }
            Frame::Padding(_) | Frame::Ping(_) => {}
            _ => unreachable!("unexpected frame: {:?} in initial packet", frame),
        }
    }
}

type HandshakePacket = (HandshakeHeader, bytes::BytesMut, usize);

impl subscribe::Subscribe<(HandshakePacket, &path::Path)> for PacketEntry {
    type Error = qbase::error::Error;

    fn deliver(
        &self,
        ((hdr, pkt, offset), path): (HandshakePacket, &path::Path),
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

        // token validation
        // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
        // Once an endpoint has successfully processed a Handshake packet from the peer, it can consider the peer
        // address to have been validated.
        // It may have already been verified using tokens in the Initial space
        path.grant_anti_amplifier();
        path.on_rcvd(rcvd_size);

        let dispatch = |is_ack_packet, frame| {
            let (frame, is_ack_eliciting) = frame?;
            self.dispatch_frame(frame, path);
            Result::<bool, Self::Error>::Ok(is_ack_packet || is_ack_eliciting)
        };
        let is_ack_packet = FrameReader::new(body_buf, hdr.get_type()).try_fold(false, dispatch)?;
        path.cc()
            .on_pkt_rcvd(qbase::Epoch::Initial, pn, is_ack_packet);
        self.rcvd_journal.register_pn(pn);

        Ok(())
    }
}
