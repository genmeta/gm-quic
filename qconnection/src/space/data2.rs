use std::{
    mem,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};

use bytes::BufMut;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{Error, QuicError},
    frame::{
        ConnectionCloseFrame, Frame, FrameReader, PathChallengeFrame, PathResponseFrame, SendFrame,
    },
    net::{
        address::BindAddr,
        route::{Link, Pathway},
        tx::{ArcSendWakers, Signals},
    },
    packet::{
        FinalPacketLayout, MarshalFrame, PacketContains, PacketWriter,
        header::{
            GetType,
            long::{ZeroRttHeader, io::LongHeaderBuilder},
            short::OneRttHeader,
        },
        keys::{
            ArcOneRttKeys, ArcOneRttPacketKeys, ArcZeroRttKeys, DirectionalKeys,
            HeaderProtectionKeys,
        },
        number::PacketNumber,
        signal::SpinBit,
        r#type::Type as PacketType,
    },
    param::{GeneralParameters, ParameterId, RememberedParameters},
    sid::{ControlStreamsConcurrency, Role},
    util::{BoundQueue, Future},
};
use qcongestion::{Feedback, Transport};
use qevent::{
    quic::{
        PacketHeader, QuicFramesCollector,
        recovery::{PacketLost, PacketLostTrigger},
        transport::PacketReceived,
    },
    telemetry::Instrument,
};
use qinterface::packet::{CipherPacket, PlainPacket};
use qrecovery::{crypto::CryptoStream, journal::ArcRcvdJournal};
#[cfg(feature = "unreliable")]
use qunreliable::DatagramFlow;
use tracing::Instrument as _;

use crate::{
    ArcReliableFrameDeque, DataJournal, DataStreams, FlowController, GuaranteedFrame,
    events::{ArcEventBroker, EmitEvent, Event},
    path::{Path, SendBuffer},
    termination::Terminator,
    tx::{PacketBuffer, PaddablePacket, Transaction},
};

pub type CipherZeroRttPacket = CipherPacket<ZeroRttHeader>;
pub type PlainZeroRttPacket = PlainPacket<ZeroRttHeader>;
pub type ReceivedZeroRttFrom = (BindAddr, CipherZeroRttPacket, Pathway, Link);

pub type CipherOneRttPacket = CipherPacket<OneRttHeader>;
pub type PlainOneRttPacket = PlainPacket<OneRttHeader>;
pub type ReceivedOneRttFrom = (BindAddr, CipherOneRttPacket, Pathway, Link);

pub struct HandshakingDataSpace {
    role: Role,
    zero_rtt_keys: ArcZeroRttKeys,
    one_rtt_keys: ArcOneRttKeys,

    crypto_stream: CryptoStream,
    reliable_frames: ArcReliableFrameDeque,
    local_params: Arc<GeneralParameters>,
    journal: DataJournal,
    stream_ctrl: Box<dyn ControlStreamsConcurrency>,
    tx_wakers: ArcSendWakers,
}

impl HandshakingDataSpace {
    pub fn new(
        role: Role,
        local_params: Arc<GeneralParameters>,
        stream_ctrl: Box<dyn ControlStreamsConcurrency>,
        reliable_frames: ArcReliableFrameDeque,
        tx_wakers: ArcSendWakers,
    ) -> Self {
        Self {
            role,
            zero_rtt_keys: ArcZeroRttKeys::new_pending(role),
            one_rtt_keys: ArcOneRttKeys::new_pending(),
            crypto_stream: CryptoStream::new(4096, 4086, tx_wakers.clone()),
            reliable_frames,
            local_params,
            journal: DataJournal::with_capacity(16, None),
            stream_ctrl,
            tx_wakers,
        }
    }

    pub fn tls_hanshake_complete(self, remote_params: &GeneralParameters) -> OneRttDataSpace {
        self.tx_wakers.wake_all_by(Signals::ONE_RTT);
        OneRttDataSpace {
            zero_rtt_keys: self.zero_rtt_keys,
            one_rtt_keys: self.one_rtt_keys,
            crypto_stream: self.crypto_stream,
            flow_ctrl: FlowController::new(
                remote_params
                    .get_as(ParameterId::InitialMaxData)
                    .expect("unreachable: default value will be got if the value unset"),
                self.local_params
                    .get_as(ParameterId::InitialMaxData)
                    .expect("unreachable: default value will be got if the value unset"),
                self.reliable_frames.clone(),
                self.tx_wakers.clone(),
            ),
            streams: DataStreams::new(
                self.role,
                self.local_params.as_ref(),
                remote_params,
                self.stream_ctrl,
                self.reliable_frames.clone(),
                self.tx_wakers.clone(),
            ),
            datagrams: DatagramFlow::new(
                self.local_params
                    .get_as(ParameterId::MaxDatagramFrameSize)
                    .unwrap(),
                self.tx_wakers.clone(),
            ),
            journal: DataJournal::with_capacity(16, remote_params.get_as(ParameterId::MaxAckDelay)),
            reliable_frames: self.reliable_frames,
        }
    }
}

pub struct ZeroRttDataSpace {
    zero_rtt_keys: ArcZeroRttKeys,
    one_rtt_keys: ArcOneRttKeys,

    // never send!
    crypto_stream: CryptoStream,
    flow_ctrl: FlowController,
    streams: DataStreams,
    datagrams: DatagramFlow,
    journal: DataJournal,
    reliable_frames: ArcReliableFrameDeque,

    tx_wakers: ArcSendWakers,
}

impl ZeroRttDataSpace {
    pub fn new(
        local_params: &GeneralParameters,
        remembered_params: &RememberedParameters,
        zero_rtt_keys: ArcZeroRttKeys,
        streams_ctrl: Box<dyn ControlStreamsConcurrency>,
        reliable_frames: ArcReliableFrameDeque,
        tx_wakers: ArcSendWakers,
    ) -> Self {
        Self {
            zero_rtt_keys,
            one_rtt_keys: ArcOneRttKeys::new_pending(),
            crypto_stream: CryptoStream::new(4096, 4086, tx_wakers.clone()),
            flow_ctrl: FlowController::new(
                remembered_params
                    .get_as(ParameterId::InitialMaxData)
                    .expect("unreachable: default value will be got if the value unset"),
                local_params
                    .get_as(ParameterId::InitialMaxData)
                    .expect("unreachable: default value will be got if the value unset"),
                reliable_frames.clone(),
                tx_wakers.clone(),
            ),
            // ok: no NOT_REDUCE parameters will be accessed
            streams: DataStreams::new(
                Role::Client,
                local_params,
                remembered_params.as_ref(),
                streams_ctrl,
                reliable_frames.clone(),
                tx_wakers.clone(),
            ),
            datagrams: DatagramFlow::new(
                local_params
                    .get_as(ParameterId::MaxDatagramFrameSize)
                    .expect("unreachable: default value will be got if the value unset"),
                tx_wakers.clone(),
            ),
            // max_ack_delay: NOT_RESUME
            journal: DataJournal::with_capacity(16, None),
            reliable_frames,
            tx_wakers,
        }
    }

    pub fn tls_hanshake_complete(
        self,
        zero_rtt_accepted: Option<bool>,
        remote_params: &GeneralParameters,
    ) -> OneRttDataSpace {
        self.tx_wakers.wake_all_by(Signals::ONE_RTT);
        if let Some(zero_rtt_accepted) = zero_rtt_accepted {
            self.streams
                .revise_params(zero_rtt_accepted, remote_params, &self.flow_ctrl.sender);
        }
        // TOOD: is this correct?
        self.journal.of_rcvd_packets().enter_one_rtt(
            remote_params
                .get_as(ParameterId::MaxAckDelay)
                .expect("unreachable: default value will be got if the value unset"),
        );
        self.zero_rtt_keys.invalid();
        // TOOD: datagram flow
        OneRttDataSpace {
            zero_rtt_keys: self.zero_rtt_keys,
            one_rtt_keys: self.one_rtt_keys,
            crypto_stream: CryptoStream::new(4096, 4086, self.tx_wakers.clone()),
            flow_ctrl: self.flow_ctrl,
            streams: self.streams,
            datagrams: self.datagrams,
            journal: self.journal,
            reliable_frames: self.reliable_frames,
        }
    }

    pub fn try_assemble_0rtt_packet(
        &self,
        tx: &mut Transaction<'_>,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        buf: &mut [u8],
    ) -> Result<PaddablePacket, Signals> {
        if self.one_rtt_keys.get_local_keys().is_some() {
            return Err(Signals::empty()); // not error, just skip 0rtt
        }

        let Some(keys) = self.zero_rtt_keys.get_encrypt_keys() else {
            return Err(Signals::empty()); // no 0rtt keys, just skip 0rtt
        };

        let (retran_timeout, expire_timeout) = tx.retransmit_and_expire_time(Epoch::Data);
        let sent_journal = self.journal.of_sent_packets();
        let mut packet = PacketBuffer::new_long(
            LongHeaderBuilder::with_cid(tx.dcid(), tx.scid()).zero_rtt(),
            buf,
            keys,
            &sent_journal,
        )?;

        let mut signals = Signals::empty();

        _ = path_challenge_frames
            .try_load_frames_into(&mut packet)
            .map_err(|s| signals |= s);
        // try to load reliable frames into this 0RTT packet to send
        _ = self
            .reliable_frames
            .try_load_frames_into(&mut packet)
            .map_err(|s| signals |= s);
        // try to load stream frames into this 0RTT packet to send
        self.streams
            .try_load_data_into(&mut packet, &self.flow_ctrl.sender)
            .map_err(|s| signals |= s)
            .unwrap_or_default();
        #[cfg(feature = "unreliable")]
        let _ = self
            .datagrams
            .try_load_data_into(&mut packet)
            .map_err(|s| signals |= s);

        // 错误是累积的，只有最后发现确实不能组成一个数据包时才真正返回错误
        packet
            .prepare_with_time(retran_timeout, expire_timeout)
            .map_err(|_| signals)
    }
}

pub async fn deliver_and_parse_0rtt(
    zeor_rtt_packets: BoundQueue<ReceivedZeroRttFrom>,
    data_sapce: Arc<DataSpace>,
    mut get_or_create_path: impl FnMut(BindAddr, Link, Pathway) -> Result<Path, Error>,
    mut dispatch_data_frame: impl for<'a> FnMut(Frame, PacketType, &'a Path),
) -> Result<(), Error> {
    while let Some((bind_addr, packet, pathway, link)) = zeor_rtt_packets.recv().await {
        let _qlog_span = qevent::span!(@current, path=pathway.to_string()).enter();
        if let Some(packet) = data_sapce.decrypt_0rtt_packet(packet).await.transpose()? {
            let path = match get_or_create_path(bind_addr, link, pathway) {
                Ok(path) => path,
                Err(_) => {
                    packet.drop_on_conenction_closed();
                    return Ok(());
                }
            };

            let mut frames = QuicFramesCollector::<PacketReceived>::new();
            let packet_contains = FrameReader::new(packet.body(), packet.get_type()).try_fold(
                PacketContains::default(),
                |packet_contains, frame| {
                    let (frame, frame_type) = frame?;
                    frames.extend(Some(&frame));
                    dispatch_data_frame(frame, packet.get_type(), &path);
                    Result::<_, QuicError>::Ok(packet_contains.include(frame_type))
                },
            )?;
            packet.log_received(frames);

            data_sapce.journal().of_rcvd_packets().register_pn(
                packet.pn(),
                packet_contains.ack_eliciting(),
                path.cc().get_pto(Epoch::Data),
            );
            path.on_packet_rcvd(Epoch::Data, packet.pn(), packet.size(), packet_contains);
        };
    }
    Ok(())
}

pub struct OneRttDataSpace {
    zero_rtt_keys: ArcZeroRttKeys,
    one_rtt_keys: ArcOneRttKeys,

    crypto_stream: CryptoStream,
    flow_ctrl: FlowController,
    streams: DataStreams,
    datagrams: DatagramFlow,
    journal: DataJournal,
    reliable_frames: ArcReliableFrameDeque,
}

impl OneRttDataSpace {
    // todo: move to data space
    pub async fn decrypt_0rtt_packet(
        &self,
        packet: CipherZeroRttPacket,
    ) -> Option<Result<PlainZeroRttPacket, QuicError>> {
        // TODO: client should never received 0rtt packet...
        match self.zero_rtt_keys.get_decrypt_keys()?.await {
            Some(keys) => {
                packet.decrypt_long_packet(keys.header.as_ref(), keys.packet.as_ref(), |pn| {
                    self.journal.of_rcvd_packets().decode_pn(pn)
                })
            }
            None => {
                packet.drop_on_key_unavailable();
                None
            }
        }
    }

    pub async fn decrypt_1rtt_packet(
        &self,
        packet: CipherOneRttPacket,
    ) -> Option<Result<PlainOneRttPacket, QuicError>> {
        match self.one_rtt_keys.get_remote_keys().await {
            Some((hpk, pk)) => packet.decrypt_short_packet(hpk.as_ref(), &pk, |pn| {
                self.journal.of_rcvd_packets().decode_pn(pn)
            }),
            None => {
                packet.drop_on_key_unavailable();
                None
            }
        }
    }

    pub fn try_assemble_1rtt_packet(
        &self,
        tx: &mut Transaction<'_>,
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
        buf: &mut [u8],
    ) -> Result<(PaddablePacket, Option<u64>), Signals> {
        let (hpk, pk) = self.one_rtt_keys.get_local_keys().ok_or(Signals::KEYS)?;
        let (key_phase, pk) = pk.lock_guard().get_local();
        let sent_journal = self.journal.of_sent_packets();
        // (1) may_loss被调用时cc已经被锁定，may_loss会尝试锁定sent_journal
        // (2) PacketMemory会持有sent_journal的guard，而need_ack会尝试锁定cc
        // 在PacketMemory存在时尝试锁定cc，可能会和 (1) 冲突:
        //   (1)持有cc，要锁定sent_journal；(2)持有sent_journal要锁定cc
        // 在多线程的情况下，可能会发生死锁。所以提前调用need_ack，避免交叉导致死锁
        let need_ack = tx.need_ack(Epoch::Data);
        let (retran_timeout, expire_timeout) = tx.retransmit_and_expire_time(Epoch::Data);
        let mut packet = PacketBuffer::new_short(
            OneRttHeader::new(spin, tx.dcid()),
            buf,
            DirectionalKeys {
                header: hpk,
                packet: pk,
            },
            key_phase,
            &sent_journal,
        )?;

        let mut signals = Signals::empty();

        let ack = need_ack
            .or_else(|| {
                let rcvd_journal = self.journal.of_rcvd_packets();
                rcvd_journal.trigger_ack_frame()
            })
            .ok_or(Signals::TRANSPORT)
            .and_then(|(largest, rcvd_time)| {
                let rcvd_journal = self.journal.of_rcvd_packets();
                let ack_frame = rcvd_journal.gen_ack_frame_util(
                    packet.pn(),
                    largest,
                    rcvd_time,
                    packet.remaining_mut(),
                )?;
                packet.dump_ack_frame(ack_frame);
                Ok(largest)
            })
            .map_err(|s| signals |= s)
            .ok();

        _ = path_challenge_frames
            .try_load_frames_into(&mut packet)
            .map_err(|s| signals |= s);
        _ = path_response_frames
            .try_load_frames_into(&mut packet)
            .map_err(|s| signals |= s);
        _ = self
            .crypto_stream
            .outgoing()
            .try_load_data_into(&mut packet)
            .map_err(|s| signals |= s);
        // try to load reliable frames into this 1RTT packet to send
        _ = self
            .reliable_frames
            .try_load_frames_into(&mut packet)
            .map_err(|s| signals |= s);
        // try to load stream frames into this 1RTT packet to send
        self.streams
            .try_load_data_into(&mut packet, &tx.flow_ctrl().sender)
            .map_err(|s| signals |= s)
            .unwrap_or_default();

        #[cfg(feature = "unreliable")]
        let _ = self
            .datagrams
            .try_load_data_into(&mut packet)
            .map_err(|s| signals |= s);

        Ok((
            packet
                .prepare_with_time(retran_timeout, expire_timeout)
                .map_err(|_| signals)?,
            ack,
        ))
    }

    pub fn try_assemble_ping_packet(
        &self,
        tx: &mut Transaction<'_>,
        spin: SpinBit,
        buf: &mut [u8],
    ) -> Result<PaddablePacket, Signals> {
        let (hpk, pk) = self.one_rtt_keys.get_local_keys().ok_or(Signals::KEYS)?;
        let (key_phase, pk) = pk.lock_guard().get_local();
        let (retran_timeout, expire_timeout) = tx.retransmit_and_expire_time(Epoch::Data);
        let sent_journal = self.journal.of_sent_packets();
        let mut packet = PacketBuffer::new_short(
            OneRttHeader::new(spin, tx.dcid()),
            buf,
            DirectionalKeys {
                header: hpk,
                packet: pk,
            },
            key_phase,
            &sent_journal,
        )?;

        packet.dump_ping_frame();

        packet
            .prepare_with_time(retran_timeout, expire_timeout)
            .map_err(|_| unreachable!("packet is not empty"))
    }
}

pub async fn deliver_and_parse_1rtt(
    one_rtt_packets: BoundQueue<ReceivedOneRttFrom>,
    data_sapce: Arc<DataSpace>,
    mut on_decrypt_success: impl FnMut(),
    mut get_or_create_path: impl FnMut(BindAddr, Link, Pathway) -> Result<Path, Error>,
    mut dispatch_data_frame: impl for<'a> FnMut(Frame, PacketType, &'a Path),
) -> Result<(), Error> {
    while let Some((bind_addr, packet, pathway, link)) = one_rtt_packets.recv().await {
        let _qlog_span = qevent::span!(@current, path=pathway.to_string()).enter();
        if let Some(packet) = data_sapce.decrypt_1rtt_packet(packet).await.transpose()? {
            on_decrypt_success();

            let path = match get_or_create_path(bind_addr, link, pathway) {
                Ok(path) => path,
                Err(_) => {
                    packet.drop_on_conenction_closed();
                    return Ok(());
                }
            };

            let mut frames = QuicFramesCollector::<PacketReceived>::new();
            let packet_contains = FrameReader::new(packet.body(), packet.get_type()).try_fold(
                PacketContains::default(),
                |packet_contains, frame| {
                    let (frame, frame_type) = frame?;
                    frames.extend(Some(&frame));
                    dispatch_data_frame(frame, packet.get_type(), &path);
                    Result::<_, QuicError>::Ok(packet_contains.include(frame_type))
                },
            )?;
            packet.log_received(frames);

            data_sapce.journal().of_rcvd_packets().register_pn(
                packet.pn(),
                packet_contains.ack_eliciting(),
                path.cc().get_pto(Epoch::Data),
            );
            path.on_packet_rcvd(Epoch::Data, packet.pn(), packet.size(), packet_contains);
        }
    }
    Ok(())
}

enum DataSpaceState {
    Handshaking {
        space: HandshakingDataSpace,
        one_rtt: Arc<Future<Arc<OneRttDataSpace>>>,
    },
    ZeroRtt {
        space: ZeroRttDataSpace,
        one_rtt: Arc<Future<Arc<OneRttDataSpace>>>,
    },
    OneRtt {
        space: Arc<OneRttDataSpace>,
    },

    Invalid,
}

pub struct DataSpace(Mutex<DataSpaceState>);

impl From<HandshakingDataSpace> for DataSpace {
    fn from(space: HandshakingDataSpace) -> Self {
        DataSpace(Mutex::new(DataSpaceState::Handshaking {
            space,
            one_rtt: Arc::new(Future::new()),
        }))
    }
}

impl From<ZeroRttDataSpace> for DataSpace {
    fn from(space: ZeroRttDataSpace) -> Self {
        DataSpace(Mutex::new(DataSpaceState::ZeroRtt {
            space,
            one_rtt: Arc::new(Future::new()),
        }))
    }
}

impl DataSpace {
    pub fn tls_hanshake_complete(
        &self,
        zero_rtt_accepted: Option<bool>,
        remote_parameters: &GeneralParameters,
    ) {
        let mut data_space_state = self.0.lock().unwrap();
        let (one_rtt_data_space, one_rtt_future) =
            match mem::replace(data_space_state.deref_mut(), DataSpaceState::Invalid) {
                DataSpaceState::Handshaking { space, one_rtt } => (
                    space.tls_hanshake_complete(remote_parameters),
                    one_rtt.clone(),
                ),
                DataSpaceState::ZeroRtt { space, one_rtt } => (
                    space.tls_hanshake_complete(zero_rtt_accepted, remote_parameters),
                    one_rtt,
                ),
                DataSpaceState::OneRtt { .. } => unreachable!("data space is already 1RTT"),
                DataSpaceState::Invalid => unreachable!("data space is invalid"),
            };
        let space = Arc::new(one_rtt_data_space);
        one_rtt_future.set(space.clone());
        *data_space_state = DataSpaceState::OneRtt { space };
    }

    pub async fn one_rtt(&self) -> Arc<OneRttDataSpace> {
        let one_rtt_data_space = match self.0.lock().unwrap().deref() {
            DataSpaceState::Handshaking { one_rtt, .. } => one_rtt.clone(),
            DataSpaceState::ZeroRtt { one_rtt, .. } => one_rtt.clone(),
            DataSpaceState::OneRtt { space } => return space.clone(),
            DataSpaceState::Invalid => unreachable!("data space is invalid"),
        };
        return one_rtt_data_space.get().await.clone();
    }

    pub fn is_one_rtt_ready(&self) -> bool {
        match self.0.lock().unwrap().deref() {
            DataSpaceState::Handshaking { .. } | DataSpaceState::ZeroRtt { .. } => false,
            DataSpaceState::OneRtt { .. } => true,
            DataSpaceState::Invalid => unreachable!("data space is invalid"),
        }
    }

    pub async fn decrypt_0rtt_packet(
        &self,
        packet: CipherZeroRttPacket,
    ) -> Option<Result<PlainZeroRttPacket, QuicError>> {
        self.one_rtt().await.decrypt_0rtt_packet(packet).await
    }

    pub async fn decrypt_1rtt_packet(
        &self,
        packet: CipherOneRttPacket,
    ) -> Option<Result<PlainOneRttPacket, QuicError>> {
        self.one_rtt().await.decrypt_1rtt_packet(packet).await
    }

    pub fn try_assemble_0rtt_packet(
        &self,
        tx: &mut Transaction<'_>,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        buf: &mut [u8],
    ) -> Result<PaddablePacket, Signals> {
        match self.0.lock().unwrap().deref_mut() {
            DataSpaceState::ZeroRtt { space, .. } => {
                space.try_assemble_0rtt_packet(tx, path_challenge_frames, buf)
            }
            DataSpaceState::Handshaking { .. } => {
                Err(Signals::empty()) // not error, just skip 0rtt
            }
            DataSpaceState::OneRtt { .. } => {
                Err(Signals::all()) // return all signals to trigger the next load
            }
            DataSpaceState::Invalid => unreachable!("data space is invalid"),
        }
    }

    pub fn try_assemble_1rtt_packet(
        &self,
        tx: &mut Transaction<'_>,
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
        buf: &mut [u8],
    ) -> Result<(PaddablePacket, Option<u64>), Signals> {
        let one_rtt_space = match self.0.lock().unwrap().deref() {
            DataSpaceState::OneRtt { space, .. } => space.clone(),
            DataSpaceState::Handshaking { .. } | DataSpaceState::ZeroRtt { .. } => {
                return Err(Signals::ONE_RTT);
            }
            DataSpaceState::Invalid => unreachable!("data space is invalid"),
        };
        one_rtt_space.try_assemble_1rtt_packet(
            tx,
            spin,
            path_challenge_frames,
            path_response_frames,
            buf,
        )
    }

    pub fn try_assemble_ping_packet(
        &self,
        tx: &mut Transaction<'_>,
        spin: SpinBit,
        buf: &mut [u8],
    ) -> Result<PaddablePacket, Signals> {
        let one_rtt_space = match self.0.lock().unwrap().deref() {
            DataSpaceState::OneRtt { space, .. } => space.clone(),
            DataSpaceState::Handshaking { .. } | DataSpaceState::ZeroRtt { .. } => {
                return Err(Signals::ONE_RTT);
            }
            DataSpaceState::Invalid => unreachable!("data space is invalid"),
        };
        one_rtt_space.try_assemble_ping_packet(tx, spin, buf)
    }

    fn journal(&self) -> DataJournal {
        match self.0.lock().unwrap().deref() {
            DataSpaceState::Handshaking { space, .. } => space.journal.clone(),
            DataSpaceState::ZeroRtt { space, .. } => space.journal.clone(),
            DataSpaceState::OneRtt { space, .. } => space.journal.clone(),
            DataSpaceState::Invalid => unreachable!("data space is invalid"),
        }
    }

    pub fn crypto_stream(&self) -> CryptoStream {
        match self.0.lock().unwrap().deref() {
            DataSpaceState::Handshaking { space, .. } => space.crypto_stream.clone(),
            DataSpaceState::ZeroRtt { space, .. } => space.crypto_stream.clone(),
            DataSpaceState::OneRtt { space, .. } => space.crypto_stream.clone(),
            DataSpaceState::Invalid => unreachable!("data space is invalid"),
        }
    }

    pub fn zero_rtt_keys(&self) -> ArcZeroRttKeys {
        match self.0.lock().unwrap().deref() {
            DataSpaceState::Handshaking { space, .. } => space.zero_rtt_keys.clone(),
            DataSpaceState::ZeroRtt { space, .. } => space.zero_rtt_keys.clone(),
            DataSpaceState::OneRtt { space } => space.zero_rtt_keys.clone(),
            DataSpaceState::Invalid => unreachable!("data space is invalid"),
        }
    }

    pub fn one_rtt_keys(&self) -> ArcOneRttKeys {
        match self.0.lock().unwrap().deref() {
            DataSpaceState::Handshaking { space, .. } => space.one_rtt_keys.clone(),
            DataSpaceState::ZeroRtt { space, .. } => space.one_rtt_keys.clone(),
            DataSpaceState::OneRtt { space } => space.one_rtt_keys.clone(),
            DataSpaceState::Invalid => unreachable!("data space is invalid"),
        }
    }

    pub async fn streams(&self) -> DataStreams {
        self.one_rtt().await.streams.clone()
    }

    pub async fn datagrams(&self) -> DatagramFlow {
        self.one_rtt().await.datagrams.clone()
    }
}

impl Feedback for DataSpace {
    fn may_loss(&self, trigger: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        // TOOD: packet type不准确
        let (packet_type, sent_jornal, crypto_outgoing, streams, reliable_frames) =
            match self.0.lock().unwrap().deref() {
                DataSpaceState::ZeroRtt { space, .. } => (
                    qevent::quic::PacketType::ZeroRTT,
                    space.journal.of_sent_packets(),
                    space.crypto_stream.outgoing(),
                    space.streams.clone(),
                    space.reliable_frames.clone(),
                ),
                DataSpaceState::OneRtt { space } => (
                    qevent::quic::PacketType::OneRTT,
                    space.journal.of_sent_packets(),
                    space.crypto_stream.outgoing(),
                    space.streams.clone(),
                    space.reliable_frames.clone(),
                ),
                DataSpaceState::Handshaking { .. } => unreachable!("never send"),
                DataSpaceState::Invalid => unreachable!("data space is invalid"),
            };

        let mut sent_packets = sent_jornal.rotate();
        for pn in pns {
            let mut may_lost_frames = QuicFramesCollector::<PacketLost>::new();
            for frame in sent_packets.may_loss_packet(pn) {
                match frame {
                    GuaranteedFrame::Crypto(frame) => {
                        may_lost_frames.extend([&frame]);
                        crypto_outgoing.may_loss_data(&frame);
                    }
                    GuaranteedFrame::Stream(frame) => {
                        may_lost_frames.extend([&frame]);
                        streams.may_loss_data(&frame);
                    }
                    GuaranteedFrame::Reliable(frame) => {
                        may_lost_frames.extend([&frame]);
                        reliable_frames.send_frame([frame]);
                    }
                };
            }
            qevent::event!(PacketLost {
                header: PacketHeader {
                    packet_type,
                    packet_number: pn
                },
                frames: may_lost_frames,
                trigger
            });
        }
    }
}

#[derive(Clone)]
pub struct ClosingDataSpace {
    keys: (HeaderProtectionKeys, ArcOneRttPacketKeys),
    ccf_packet_pn: (u64, PacketNumber),
    rcvd_journal: ArcRcvdJournal,
}

impl DataSpace {
    pub fn close(&self) -> Option<ClosingDataSpace> {
        let state = self.0.lock().unwrap();
        let data_space = match state.deref() {
            DataSpaceState::OneRtt { space } => space,
            DataSpaceState::Handshaking { .. } | DataSpaceState::ZeroRtt { .. } => return None,
            DataSpaceState::Invalid => unreachable!("data space is invalid"),
        };
        let keys = data_space.one_rtt_keys.invalid()?;
        let sent_journal = data_space.journal.of_sent_packets();
        let new_packet_guard = sent_journal.new_packet();
        let ccf_packet_pn = new_packet_guard.pn();
        let rcvd_journal = data_space.journal.of_rcvd_packets();
        Some(ClosingDataSpace {
            rcvd_journal,
            ccf_packet_pn,
            keys,
        })
    }
}

impl ClosingDataSpace {
    pub fn recv_packet(&self, packet: CipherOneRttPacket) -> Option<ConnectionCloseFrame> {
        let packet = packet
            .decrypt_short_packet(self.keys.0.remote.as_ref(), &self.keys.1, |pn| {
                self.rcvd_journal.decode_pn(pn)
            })
            .and_then(Result::ok)?;

        let mut frames = QuicFramesCollector::<PacketReceived>::new();
        let ccf = FrameReader::new(packet.body(), packet.get_type())
            .filter_map(Result::ok)
            .inspect(|(f, _ack)| frames.extend(Some(f)))
            .fold(None, |ccf, (frame, _)| match (ccf, frame) {
                (ccf @ Some(..), _) => ccf,
                (None, Frame::Close(ccf)) => Some(ccf),
                (None, _) => None,
            });
        packet.log_received(frames);
        ccf
    }

    pub fn try_assemble_ccf_packet(
        &self,
        dcid: ConnectionId,
        ccf: &ConnectionCloseFrame,
        buf: &mut [u8],
    ) -> Option<FinalPacketLayout> {
        let (hpk, pk) = &self.keys;
        let (key_phase, pk) = pk.lock_guard().get_local();
        let header = OneRttHeader::new(Default::default(), dcid);
        let pn = self.ccf_packet_pn;
        // 装填ccf时ccf不在乎Limiter
        let mut packet_writer = PacketWriter::new_short(
            &header,
            buf,
            pn,
            DirectionalKeys {
                header: hpk.local.clone(),
                packet: pk,
            },
            key_phase,
        )
        .ok()?;

        packet_writer.dump_frame(ccf.clone());

        Some(packet_writer.encrypt_and_protect())
    }
}

pub fn spawn_deliver_and_parse_closing(
    packets: BoundQueue<ReceivedOneRttFrom>,
    space: ClosingDataSpace,
    terminator: Arc<Terminator>,
    event_broker: ArcEventBroker,
) {
    tokio::spawn(
        async move {
            while let Some((_, packet, pathway, _socket)) = packets.recv().await {
                if let Some(ccf) = space.recv_packet(packet) {
                    event_broker.emit(Event::Closed(ccf.clone()));
                    return;
                }
                if terminator.should_send() {
                    _ = terminator
                        .try_send_with(pathway, |buf, _scid, dcid, ccf| {
                            space
                                .try_assemble_ccf_packet(dcid?, ccf, buf)
                                .map(|layout| layout.sent_bytes())
                        })
                        .await;
                }
            }
        }
        .instrument_in_current()
        .in_current_span(),
    );
}
