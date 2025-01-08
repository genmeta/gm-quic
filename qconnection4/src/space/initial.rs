use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use bytes::BufMut;
use futures::{Stream, StreamExt};
use qbase::{
    cid::ConnectionId,
    error::Error,
    frame::{ConnectionCloseFrame, Frame, FrameReader},
    packet::{
        decrypt::{decrypt_packet, remove_protection_of_long_packet},
        header::{
            long::{io::LongHeaderBuilder, InitialHeader},
            GetScid, GetType,
        },
        keys::ArcKeys,
        number::PacketNumber,
        AssembledPacket, MarshalFrame, MiddleAssembledPacket, PacketWriter,
    },
    token::TokenRegistry,
    Epoch,
};
use qcongestion::{CongestionControl, TrackPackets};
use qinterface::{closing::ClosingInterface, path::Pathway};
use qrecovery::{
    crypto::{CryptoStream, CryptoStreamOutgoing},
    journal::{ArcRcvdJournal, InitialJournal},
};
use rustls::quic::Keys;
use tokio::sync::mpsc;

use super::{pipe, AckInitial, DecryptedPacket};
use crate::{
    events::{EmitEvent, Event},
    path::{ArcPaths, Path},
    tx::{PacketMemory, Transaction},
    Components,
};

pub type InitialPacket = (InitialHeader, bytes::BytesMut, usize);
pub type DecryptedInitialPacket = DecryptedPacket<InitialHeader>;

#[derive(Clone)]
pub struct InitialSpace {
    pub keys: ArcKeys,
    pub crypto_stream: CryptoStream,
    token: Arc<Mutex<Vec<u8>>>,
    journal: InitialJournal,
}

impl InitialSpace {
    // Initial keys应该是预先知道的，或者传入dcid，可以构造出来
    pub fn new(keys: rustls::quic::Keys, token: Vec<u8>) -> Self {
        let journal = InitialJournal::with_capacity(16);
        let crypto_stream = CryptoStream::new(4096, 4096);

        Self {
            token: Arc::new(Mutex::new(token)),
            keys: ArcKeys::with_keys(keys),
            journal,
            crypto_stream,
        }
    }

    pub async fn decrypt_packet(
        &self,
        (header, mut payload, offset): InitialPacket,
    ) -> Option<Result<DecryptedInitialPacket, Error>> {
        let keys = self.keys.get_remote_keys().await?;
        let (hpk, pk) = (keys.remote.header.as_ref(), keys.remote.packet.as_ref());

        let undecoded_pn =
            match remove_protection_of_long_packet(hpk, payload.as_mut(), offset).transpose()? {
                Ok(undecoded_pn) => undecoded_pn,
                Err(invalid_reversed_bits) => return Some(Err(invalid_reversed_bits.into())),
            };
        let rcvd_journal = self.journal.of_rcvd_packets();
        let pn = rcvd_journal.decode_pn(undecoded_pn).ok()?;
        let body_offset = offset + undecoded_pn.size();
        let pkt_len = decrypt_packet(pk, pn, payload.as_mut(), body_offset).ok()?;

        let _header = payload.split_to(body_offset);
        payload.truncate(pkt_len);

        Some(Ok(DecryptedInitialPacket {
            header,
            pn,
            payload: payload.freeze(),
        }))
    }

    /// TODO: 还要padding、加密等功能，理应返回一个PacketWriter+密钥，以防后续还要padding
    ///     或者提供一个不需外部计算padding的接口，比如先填充Initial之外的包，最后再填充Initial，提供最小长度
    pub fn try_assemble<'b>(
        &self,
        tx: &mut Transaction<'_>,
        buf: &'b mut [u8],
    ) -> Option<(MiddleAssembledPacket, Option<u64>)> {
        let keys = self.keys.get_local_keys()?;
        let sent_journal = self.journal.of_sent_packets();
        let mut packet = PacketMemory::new_long(
            LongHeaderBuilder::with_cid(tx.dcid(), tx.scid())
                .initial(self.token.lock().unwrap().clone()),
            buf,
            keys,
            &sent_journal,
        )?;

        let mut ack = None;
        if let Some((largest, rcvd_time)) = tx.need_ack(Epoch::Initial) {
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

        let packet: PacketWriter<'b> = packet.try_into().ok()?;
        Some((packet.abandon(), ack))
    }

    pub fn tracker(&self) -> InitialTracker {
        InitialTracker {
            journal: self.journal.clone(),
            outgoing: self.crypto_stream.outgoing().clone(),
        }
    }
}

pub fn launch_deliver_and_parse(
    mut packets: impl Stream<Item = (InitialPacket, Pathway)> + Unpin + Send + 'static,
    space: &InitialSpace,
    paths: &ArcPaths,
    components: &Components,
    event_broker: impl EmitEvent + Clone + Send + Sync + 'static,
) {
    let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded_channel();
    let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded_channel();

    pipe(
        rcvd_crypto_frames,
        space.crypto_stream.incoming(),
        event_broker.clone(),
    );
    pipe(
        rcvd_ack_frames,
        AckInitial::new(&space.journal, &space.crypto_stream),
        event_broker.clone(),
    );

    let parameters = components.parameters.clone();
    let validate = {
        let tls_session = components.tls_session.clone();
        let token_registry = components.token_registry.clone();
        move |initial_token: &[u8], path: &Path| {
            if let TokenRegistry::Server(provider) = token_registry.deref() {
                if let Some(server_name) = tls_session.server_name() {
                    if provider.verify_token(server_name, initial_token) {
                        path.grant_anti_amplifier();
                    }
                }
            }
        }
    };

    let space = space.clone();
    let paths = paths.clone();
    tokio::spawn(async move {
        while let Some((packet, pathway)) = packets.next().await {
            let Some(path) = paths.get(&pathway) else {
                continue;
            };
            let dispatch_frame = {
                |frame: Frame| match frame {
                    Frame::Ack(f) => {
                        path.cc().on_ack(Epoch::Initial, &f);
                        _ = ack_frames_entry.send(f);
                    }
                    Frame::Close(f) => event_broker.emit(Event::Closed(f)),
                    Frame::Crypto(f, bytes) => _ = crypto_frames_entry.send((f, bytes)),
                    Frame::Padding(_) | Frame::Ping(_) => {}
                    _ => unreachable!("unexpected frame: {:?} in handshake packet", frame),
                }
            };
            match space.decrypt_packet(packet).await {
                Some(Ok(packet)) => {
                    match FrameReader::new(packet.payload, packet.header.get_type()).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame);
                            Result::<bool, Error>::Ok(is_ack_packet || is_ack_eliciting)
                        },
                    ) {
                        Ok(is_ack_packet) => {
                            space.journal.of_rcvd_packets().register_pn(packet.pn);
                            path.cc()
                                .on_pkt_rcvd(Epoch::Handshake, packet.pn, is_ack_packet);
                            // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
                            // A server might wish to validate the client address before starting the cryptographic handshake.
                            // QUIC uses a token in the Initial packet to provide address validation prior to completing the handshake.
                            // This token is delivered to the client during connection establishment with a Retry packet (see Section 8.1.2)
                            // or in a previous connection using the NEW_TOKEN frame (see Section 8.1.3).
                            // only the first cid will be set
                            parameters.initial_scid_from_peer_need_equal(*packet.header.get_scid());
                            if !packet.header.token.is_empty() {
                                validate(&packet.header.token, &path);
                            }
                        }
                        Err(error) => event_broker.emit(Event::Failed(error)),
                    }
                }
                Some(Err(error)) => event_broker.emit(Event::Failed(error)),
                None => continue,
            }
        }
    });
}

#[derive(Clone)]
pub struct InitialTracker {
    journal: InitialJournal,
    outgoing: CryptoStreamOutgoing,
}

impl TrackPackets for InitialTracker {
    fn may_loss(&self, pn: u64) {
        for frame in self.journal.of_sent_packets().rotate().may_loss_pkt(pn) {
            self.outgoing.may_loss_data(&frame);
        }
    }

    fn retire(&self, pn: u64) {
        self.journal.of_rcvd_packets().write().retire(pn);
    }
}

#[derive(Clone)]
pub struct ClosingInitialSpace {
    rcvd_journal: ArcRcvdJournal,
    ccf_packet_pn: (u64, PacketNumber),
    keys: Arc<Keys>,
}

impl InitialSpace {
    pub fn close(self) -> Option<ClosingInitialSpace> {
        let keys = self.keys.get_local_keys()?;
        let sent_journal = self.journal.of_sent_packets();
        let new_packet_guard = sent_journal.new_packet();
        let ccf_packet_pn = new_packet_guard.pn();
        let rcvd_journal = self.journal.of_rcvd_packets();
        Some(ClosingInitialSpace {
            rcvd_journal,
            ccf_packet_pn,
            keys,
        })
    }
}

impl ClosingInitialSpace {
    pub fn recv_packet(
        &self,
        (header, mut bytes, offset): InitialPacket,
    ) -> Option<ConnectionCloseFrame> {
        let (hpk, pk) = (
            self.keys.remote.header.as_ref(),
            self.keys.remote.packet.as_ref(),
        );
        let undecoded_pn = remove_protection_of_long_packet(hpk, bytes.as_mut(), offset).ok()??;

        let pn = self.rcvd_journal.decode_pn(undecoded_pn).ok()?;
        let body_offset = offset + undecoded_pn.size();
        let _pkt_len = decrypt_packet(pk, pn, bytes.as_mut(), body_offset).ok()?;

        FrameReader::new(bytes.freeze(), header.get_type())
            .filter_map(Result::ok)
            .find_map(|(f, _ack)| match f {
                Frame::Close(ccf) => Some(ccf),
                _ => None,
            })
    }

    pub fn try_assemble_ccf_packet(
        &self,
        scid: ConnectionId,
        dcid: ConnectionId,
        ccf: &ConnectionCloseFrame,
        buf: &mut [u8],
    ) -> Option<AssembledPacket> {
        let header = LongHeaderBuilder::with_cid(scid, dcid).handshake();
        let pn = self.ccf_packet_pn;
        let mut packet_writer = PacketWriter::new_long(&header, buf, pn, self.keys.clone())?;

        packet_writer.dump_frame(ccf.clone());

        Some(packet_writer.encrypt_and_protect())
    }
}

pub fn launch_deliver_and_parse_closing(
    mut packets: impl Stream<Item = (InitialPacket, Pathway)> + Unpin + Send + 'static,
    space: ClosingInitialSpace,
    closing_iface: Arc<ClosingInterface>,
    event_broker: impl EmitEvent + Clone + Send + 'static,
) {
    tokio::spawn(async move {
        while let Some((packet, pathway)) = packets.next().await {
            if let Some(ccf) = space.recv_packet(packet) {
                event_broker.emit(Event::Closed(ccf.clone()));
                return;
            }
            if closing_iface.should_send() {
                _ = closing_iface
                    .try_send_with(pathway, pathway.dst(), |buf, scid, dcid, ccf| {
                        space
                            .try_assemble_ccf_packet(scid?, dcid?, ccf, buf)
                            .map(|packet| packet.size())
                    })
                    .await;
            }
        }
    });
}
