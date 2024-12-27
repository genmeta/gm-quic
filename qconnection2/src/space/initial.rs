use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use bytes::BufMut as _;
use qbase::{
    frame::{CryptoFrame, Frame, FrameReader, ReceiveFrame as _},
    packet::{
        self,
        header::{long::InitialHeader, GetScid as _, GetType as _},
        keys,
    },
    param, token,
};
use qcongestion::CongestionControl as _;
use qrecovery::{crypto, journal};

use crate::{builder, conn, path, tls, tx, util::subscribe};

#[derive(Clone)]
pub struct Space {
    token: Arc<Mutex<Vec<u8>>>,
    keys: keys::ArcKeys,
    journal: journal::InitialJournal,
    crypto_stream: crypto::CryptoStream,
}

impl Space {
    pub fn new(keys: rustls::quic::Keys, token: Vec<u8>) -> Self {
        Self {
            token: Arc::new(token.into()),
            keys: keys::ArcKeys::with_keys(keys),
            journal: journal::InitialJournal::with_capacity(16),
            crypto_stream: crypto::CryptoStream::new(4096, 4096),
        }
    }

    // todo: 暂时只检测密钥
    pub fn has_pending_data(&self) -> bool {
        self.keys.get_local_keys().is_some() // && ...
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
            packet::header::LongHeaderBuilder::with_cid(tx.dcid(), tx.scid())
                .initial(self.token.lock().unwrap().clone()),
            buf,
            keys.local.packet.tag_len(),
            &sent_journal,
        )?;

        let mut ack = None;
        if let Some((largest, rcvd_time)) = tx.need_ack(qbase::Epoch::Initial) {
            let rcvd_journal = self.journal.of_rcvd_packets();
            if let Some(ack_frame) =
                rcvd_journal.gen_ack_frame_util(largest, rcvd_time, packet.remaining_mut())
            {
                packet.dump_ack_frame(ack_frame);
                ack = Some(largest);
            }
        }

        let crypto_stream_outgoing = self.crypto_stream.outgoing();
        crypto_stream_outgoing.try_load_data_into(&mut packet);

        if !packet.is_empty() && fill {
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

    pub(crate) fn crypto_stream(&self) -> &crypto::CryptoStream {
        &self.crypto_stream
    }
}

#[derive(Clone)]
pub struct Tracker {
    journal: journal::InitialJournal,
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

    // validata token
    tls_session: tls::ArcTlsSession,
    cid_registry: conn::CidRegistry,
    token_registry: token::ArcTokenRegistry,

    parameters: param::ArcParameters,
}

impl PacketEntry {
    pub async fn new(space: Space, components: builder::Components) -> Option<Self> {
        let keys = space.keys.get_remote_keys().await?;
        let crypto_stream_incoming = space.crypto_stream.incoming();
        let crypto_stream_outgoing = space.crypto_stream.outgoing();
        let sent_journal = space.journal.of_sent_packets();
        let rcvd_journal = space.journal.of_rcvd_packets();

        let tls_session = components.tls_session.clone();
        let cid_registry = components.cid_registry.clone();
        let token_registry = components.token_registry.clone();

        let parameters = components.parameters.clone();

        Some(Self {
            keys,
            crypto_stream_incoming,
            crypto_stream_outgoing,
            sent_journal,
            rcvd_journal,
            tls_session,
            cid_registry,
            token_registry,
            parameters,
        })
    }

    fn dispatch_frame(&self, frame: Frame, path: &path::Path) {
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
            Frame::Close(_) => { /* trustless */ }
            Frame::Padding(_) | Frame::Ping(_) => {}
            _ => unreachable!("unexpected frame: {:?} in initial packet", frame),
        }
    }
}

type InitialPacket = (InitialHeader, bytes::BytesMut, usize);

impl subscribe::Subscribe<(InitialPacket, &path::Path)> for PacketEntry {
    type Error = qbase::error::Error;

    fn deliver(
        &self,
        ((hdr, pkt, offset), path): (InitialPacket, &path::Path),
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
        // When receiving the initial packet, change the DCID of the
        // path to the SCID carried in the received packet.
        self.cid_registry
            .remote
            .revise_initial_dcid(*hdr.get_scid());

        let dispatch = |is_ack_packet, frame| {
            let (frame, is_ack_eliciting) = frame?;
            self.dispatch_frame(frame, path);
            Result::<bool, Self::Error>::Ok(is_ack_packet || is_ack_eliciting)
        };
        let is_ack_packet = FrameReader::new(body_buf, hdr.get_type()).try_fold(false, dispatch)?;
        path.cc()
            .on_pkt_rcvd(qbase::Epoch::Initial, pn, is_ack_packet);
        self.rcvd_journal.register_pn(pn);

        // token validation
        if !hdr.token.is_empty() {
            if let token::TokenRegistry::Server(provider) = self.token_registry.deref() {
                if let Some(server_name) = self.tls_session.server_name() {
                    if provider.verify_token(server_name, &hdr.token) {
                        path.grant_anti_amplifier();
                    }
                }
            }
        }

        self.parameters
            .initial_scid_from_peer_need_equal(*hdr.get_scid());

        Ok(())
    }
}
