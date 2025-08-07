use std::{
    io,
    ops::Deref,
    sync::{Arc, atomic::Ordering::Acquire},
};

use bytes::BufMut;
use derive_more::From;
use qbase::{
    Epoch, GetEpoch,
    cid::{BorrowedCid, ConnectionId},
    frame::{AckFrame, PingFrame},
    net::tx::{ArcSendWaker, Signals},
    packet::{
        MarshalFrame,
        header::{
            long::{HandshakeHeader, InitialHeader, ZeroRttHeader, io::LongHeaderBuilder},
            short::OneRttHeader,
        },
        io::{
            AssemblePacket, FinalPacketLayout, Package, PacketWriter as BasePacketWriter,
            ProductHeader, empty, fn_package, frame, pad_probe, pad_to_20, pad_to_full, repeat,
        },
        signal::SpinBit,
    },
    role::Role,
    token::TokenRegistry,
};
use qcongestion::{ArcCC, Transport};
use qrecovery::journal::{ArcRcvdJournal, Journal};

use crate::{
    ArcDcidCell, ArcReliableFrameDeque, CidRegistry, Components,
    path::{AntiAmplifier, Constraints},
    space::{Spaces, data::DataSpace, handshake::HandshakeSpace, initial::InitialSpace},
    tls::ArcTlsHandshake,
    tx::PacketWriter,
};

/// Trait alias
pub trait PackageIntoSpacePacketWriter<H, S: PacketSpace<H>>:
    for<'b, 's> Package<PacketWriter<'b, 's, S::JournalFrame>>
{
}

impl<H, S: PacketSpace<H>, P> PackageIntoSpacePacketWriter<H, S> for P where
    P: for<'b, 's> Package<PacketWriter<'b, 's, S::JournalFrame>>
{
}

pub trait PacketSpace<H> {
    type JournalFrame;

    fn new_packet<'b, 's>(
        &'s self,
        header: H,
        cc: &ArcCC,
        buffer: &'b mut [u8],
    ) -> Result<PacketWriter<'b, 's, Self::JournalFrame>, Signals>;
}

fn ack_package<'b, 's, S, F, P>(space: &'s S, cc: &ArcCC) -> impl Package<P, Output = u64> + 's
where
    S: AsRef<Journal<F>> + GetEpoch,
    P: BufMut + MarshalFrame<AckFrame> + AsRef<BasePacketWriter<'b>> + ?Sized,
{
    // (1) may_loss被调用时cc已经被锁定，may_loss会尝试锁定sent_journal
    // (2) PacketMemory会持有sent_journal的guard，而need_ack会尝试锁定cc
    // 在PacketMemory存在时尝试锁定cc，可能会和 (1) 冲突:
    //   (1)持有cc，要锁定sent_journal；(2)持有sent_journal要锁定cc
    // 在多线程的情况下，可能会发生死锁。所以提前调用need_ack，避免交叉导致死锁
    let need_ack = cc.need_ack(space.epoch());
    fn_package(move |packet_writer: &mut P| {
        let rcvd_journal: &ArcRcvdJournal = space.as_ref().as_ref();

        let (largest_ack, rcvd_time) = need_ack
            .or_else(|| rcvd_journal.need_ack())
            .ok_or(Signals::TRANSPORT)?;

        let ack_frame = rcvd_journal.gen_ack_frame_util(
            packet_writer.as_ref().pn(),
            largest_ack,
            rcvd_time,
            packet_writer.remaining_mut(),
        )?;

        packet_writer.dump_frame(ack_frame);
        Ok(largest_ack)
    })
}

pub struct Burst {
    path: Arc<super::Path>,
    initial_token: Vec<u8>,
    cid_registry: CidRegistry,
    spin: bool,

    spaces: Spaces,

    tls_handshake: ArcTlsHandshake,
}

impl super::Path {
    pub fn new_burst(self: &Arc<Self>, components: &Components) -> Burst {
        Burst {
            path: self.clone(),
            initial_token: match components.token_registry.deref() {
                TokenRegistry::Client((server_name, token_sink)) => {
                    token_sink.fetch_token(server_name)
                }
                TokenRegistry::Server(..) => vec![],
            },
            cid_registry: components.cid_registry.clone(),
            spin: false, // TODO
            spaces: components.spaces.clone(),
            tls_handshake: components.tls_handshake.clone(),
        }
    }
}

#[derive(From)]
pub enum BurstError {
    Signals(Signals),
    PathDeactived,
}

pub struct PacketsAssembler<'a> {
    cc: &'a ArcCC,
    constraints: Constraints,
    cid_registry: &'a CidRegistry,
    borrowed_dcid: Result<BorrowedCid<'a, ArcReliableFrameDeque>, Signals>,
    initial_token: &'a [u8],
    spin: SpinBit,
}

impl<'a> PacketsAssembler<'a> {
    fn new(
        cid_registry: &'a CidRegistry,
        dcid_cell: &'a ArcDcidCell,
        anti_amplifier: &AntiAmplifier,
        cc: &'a ArcCC,
        tx_waker: ArcSendWaker,
        initial_token: &'a [u8],
        spin: impl Into<SpinBit>,
    ) -> Result<PacketsAssembler<'a>, BurstError> {
        let send_quota = cc.send_quota()?;
        let Some(credit_limit) = anti_amplifier.balance()? else {
            return Err(BurstError::PathDeactived);
        };

        let Some(borrowed_dcid) = dcid_cell.borrow_cid(tx_waker).transpose() else {
            return Err(BurstError::PathDeactived);
        };

        let constraints = Constraints::new(credit_limit, send_quota);
        Ok(Self {
            cid_registry,
            borrowed_dcid,
            cc,
            constraints,
            initial_token,
            spin: spin.into(),
        })
    }

    fn initial_scid(&self) -> Result<ConnectionId, Signals> {
        self.cid_registry
            .local
            .initial_scid()
            .ok_or(Signals::empty())
    }

    fn applied_dcid(&self) -> Result<ConnectionId, Signals> {
        self.borrowed_dcid.as_deref().copied().map_err(|e| *e)
    }

    /// Return the connection ID that used to send the initial and zero rtt packets.
    ///
    /// gm-quic implements multi-path handshake feature, the client creates many paths and sends initial packets.
    ///
    /// Client will only use origin_dcid to send initial and zero rtt packets.
    ///
    /// The client and server must negotiate a handshake path and assign the initial dcid to this path
    /// to prevent the unique connection ID from being obtained by an invalid path, causing the connection to fail.
    ///
    /// The client and server choose the path where they receive the first initial packet as the handshake path.
    /// The server will only return the initial packet on the handshake path to negotiate the handshake path.
    ///
    /// Therefore, for the server, it can only send the initial packet with the connection ID assigned to the path.
    /// This manifests itself during the handshake as sending the initial packet only on the first path.
    fn initial_dcid(&self) -> Result<ConnectionId, Signals> {
        match self.cid_registry.role() {
            Role::Client => Ok(self.cid_registry.origin_dcid()),
            Role::Server => self.applied_dcid(),
        }
    }

    pub fn commit(&mut self, epoch: Epoch, final_layout: FinalPacketLayout, ack: Option<u64>) {
        self.constraints
            .commit(final_layout.sent_bytes(), final_layout.in_flight());
        self.cc.on_pkt_sent(
            epoch,
            final_layout.pn(),
            final_layout.is_ack_eliciting(),
            final_layout.sent_bytes(),
            final_layout.in_flight(),
            ack,
        );
    }
}

impl ProductHeader<InitialHeader> for PacketsAssembler<'_> {
    fn new_header(&self) -> Result<InitialHeader, Signals> {
        Ok(
            LongHeaderBuilder::with_cid(self.initial_dcid()?, self.initial_scid()?)
                .initial(self.initial_token.to_vec()),
        )
    }
}

impl ProductHeader<ZeroRttHeader> for PacketsAssembler<'_> {
    fn new_header(&self) -> Result<ZeroRttHeader, Signals> {
        Ok(LongHeaderBuilder::with_cid(self.initial_dcid()?, self.initial_scid()?).zero_rtt())
    }
}

impl ProductHeader<HandshakeHeader> for PacketsAssembler<'_> {
    fn new_header(&self) -> Result<HandshakeHeader, Signals> {
        Ok(LongHeaderBuilder::with_cid(self.applied_dcid()?, self.initial_scid()?).handshake())
    }
}

impl ProductHeader<OneRttHeader> for PacketsAssembler<'_> {
    fn new_header(&self) -> Result<OneRttHeader, Signals> {
        Ok(OneRttHeader::new(self.spin, self.applied_dcid()?))
    }
}

impl<'a> PacketsAssembler<'a> {
    pub fn assemble<'s, 'b, H, Space, P, O>(
        &mut self,
        space: &'s Space,
        packages: P,
        buffer: &'b mut [u8],
    ) -> Result<usize, Signals>
    where
        Self: ProductHeader<H>,
        Space: PacketSpace<H> + GetEpoch,
        Space::JournalFrame: 's,
        P: Package<PacketWriter<'b, 's, Space::JournalFrame>, Output = (Option<u64>, O)>,
    {
        let buffer = self.constraints.constrain(buffer);
        let mut packet = space.new_packet(self.new_header()?, self.cc, buffer)?;
        let (outputs, ..) = packet.assemble_packet(&mut (packages, pad_to_20()))?;
        let layout = packet.encrypt_and_protect_packet();
        self.commit(space.epoch(), layout, outputs.and_then(|(ack, ..)| ack));
        Result::<_, Signals>::Ok(layout.sent_bytes())
    }
}

impl Components {
    pub(super) fn packages(
        &self,
    ) -> (
        impl PackageIntoSpacePacketWriter<InitialHeader, InitialSpace>,
        impl PackageIntoSpacePacketWriter<ZeroRttHeader, DataSpace>,
        impl PackageIntoSpacePacketWriter<HandshakeHeader, HandshakeSpace>,
        impl PackageIntoSpacePacketWriter<OneRttHeader, DataSpace>,
    ) {
        let initial_packages = self.crypto_streams[Epoch::Initial]
            .outgoing()
            .package(Epoch::Initial);
        let zero_rtt_packages = (
            // repeat to send multi reliable frames in one packet
            repeat(self.reliable_frames.clone()),
            // repeat to send multi stream frames in one packet
            repeat(
                self.data_streams
                    .package(self.flow_ctrl.sender.clone(), true),
            ),
            // TODO: datagram
        );
        let handshake_packages = self.crypto_streams[Epoch::Handshake]
            .outgoing()
            .package(Epoch::Handshake);
        let one_rtt_packages = (
            self.crypto_streams[Epoch::Data]
                .outgoing()
                .package(Epoch::Data),
            // repeat to send multi reliable frames in one packet
            repeat(self.reliable_frames.clone()),
            // repeat to send multi stream frames in one packet
            repeat(
                self.data_streams
                    .package(self.flow_ctrl.sender.clone(), false),
            ),
            // TODO: datagram
        );
        (
            initial_packages,
            zero_rtt_packages,
            handshake_packages,
            one_rtt_packages,
        )
    }
}

impl Burst {
    fn assembler<'a>(&'a self) -> Result<PacketsAssembler<'a>, BurstError> {
        PacketsAssembler::new(
            &self.cid_registry,
            &self.path.dcid_cell,
            &self.path.anti_amplifier,
            &self.path.cc,
            self.path.tx_waker.clone(),
            &self.initial_token,
            self.spin,
        )
    }

    fn load_spaces<I, Z, H, O>(
        &self,
        (initial, zero_rtt, handshake, one_rtt): &mut (I, Z, H, O),
        mut buffer: &mut [u8],
    ) -> Result<usize, BurstError>
    where
        I: PackageIntoSpacePacketWriter<InitialHeader, InitialSpace>,
        Z: PackageIntoSpacePacketWriter<ZeroRttHeader, DataSpace>,
        H: PackageIntoSpacePacketWriter<HandshakeHeader, HandshakeSpace>,
        O: PackageIntoSpacePacketWriter<OneRttHeader, DataSpace>,
    {
        let Self {
            path,
            spaces,
            tls_handshake,
            ..
        } = self;

        let initial_space = spaces.initial().as_ref();
        let handshake_space = spaces.handshake().as_ref();
        let data_space = spaces.data().as_ref();

        let origin = buffer.remaining_mut();

        let mut assembler = self.assembler()?;
        let mut signals = Signals::empty();

        let Ok(tls_fin) = tls_handshake.is_finished() else {
            return Err(BurstError::PathDeactived);
        };

        let initial_ack = ack_package(initial_space, &path.cc);
        match assembler.assemble(initial_space, (initial_ack, initial), buffer) {
            Ok(bytes_sent) => buffer = buffer[bytes_sent..].as_mut(),
            Err(s) => signals |= s,
        };

        let loaded_initial = buffer.remaining_mut() != origin;

        if !tls_fin {
            match assembler.assemble::<ZeroRttHeader, _, _, _>(
                data_space,
                (empty(), zero_rtt),
                buffer,
            ) {
                Ok(bytes_sent) => buffer = buffer[bytes_sent..].as_mut(),
                Err(s) => signals |= s,
            }
        }

        let handshake_ack = ack_package(handshake_space, &path.cc);
        match assembler.assemble(handshake_space, (handshake_ack, handshake), buffer) {
            Ok(bytes_sent) => buffer = buffer[bytes_sent..].as_mut(),
            Err(s) => signals |= s,
        }

        if tls_fin {
            let ack_package = ack_package(data_space, &path.cc);
            let probe_packages = (&path.challenge_sndbuf, &path.response_sndbuf);
            let result = if path.validated.load(Acquire) {
                let packages = (
                    probe_packages,
                    one_rtt,
                    loaded_initial.then(pad_to_full),
                    pad_probe(),
                );
                assembler.assemble::<OneRttHeader, _, _, _>(
                    data_space,
                    (ack_package, packages),
                    buffer,
                )
            } else {
                let packages = (probe_packages, pad_probe());
                assembler.assemble::<OneRttHeader, _, _, _>(
                    data_space,
                    (ack_package, packages),
                    buffer,
                )
            };

            match result {
                Ok(bytes_sent) => buffer = buffer[bytes_sent..].as_mut(),
                Err(s) => signals |= s,
            }
        }

        if loaded_initial {
            assert!(buffer.remaining_mut() != origin);
            buffer.put_bytes(0, buffer.remaining_mut());
            return Ok(origin);
        }

        let sent_bytes = origin - buffer.remaining_mut();
        (sent_bytes > 0)
            .then_some(sent_bytes)
            .ok_or(BurstError::Signals(signals))
    }
}

fn ping_package<'a, P>(cc: &'a ArcCC, epoch: Epoch) -> impl Package<P, Output = ()> + 'a
where
    P: BufMut + MarshalFrame<PingFrame>,
{
    // avoid deadlock, same as ack_package
    let need_send_ack_eliciting = cc.need_send_ack_eliciting(epoch);
    fn_package(move |packet_writer: &mut P| {
        if need_send_ack_eliciting > 0 {
            return frame(PingFrame).dump(packet_writer);
        }
        // TODO: refactor signal names
        Err(Signals::PING)
    })
}

impl Burst {
    fn load_ping(&self, buffer: &mut [u8]) -> Result<usize, BurstError> {
        let Self { spaces, path, .. } = self;

        let mut assembler = self.assembler()?;
        let mut signals = Signals::empty();

        for &epoch in Epoch::iter().rev() {
            let result = match epoch {
                Epoch::Data => {
                    let ack_package = ack_package(spaces.data().as_ref(), &path.cc);
                    let ping_package = ping_package(&path.cc, epoch);
                    assembler.assemble::<OneRttHeader, _, _, _>(
                        spaces.data().as_ref(),
                        (ack_package, (ping_package, pad_to_full())),
                        buffer,
                    )
                }
                Epoch::Handshake => {
                    let ack_package = ack_package(spaces.handshake().as_ref(), &path.cc);
                    let ping_package = ping_package(&path.cc, epoch);
                    assembler.assemble(
                        spaces.handshake().as_ref(),
                        (ack_package, (ping_package, pad_to_full())),
                        buffer,
                    )
                }
                Epoch::Initial => {
                    let ack_package = ack_package(spaces.initial().as_ref(), &path.cc);
                    let ping_package = ping_package(&path.cc, epoch);
                    assembler.assemble(
                        spaces.initial().as_ref(),
                        (ack_package, (ping_package, pad_to_full())),
                        buffer,
                    )
                }
            };

            match result {
                Ok(sent_bytes) => return Ok(sent_bytes),
                Err(s) => signals |= s,
            }
        }

        Err(BurstError::Signals(signals))
    }

    fn load_heartbeat(&self, buffer: &mut [u8]) -> Result<usize, BurstError> {
        let Self { spaces, path, .. } = self;

        let mut assembler = self.assembler()?;
        let ack_package = ack_package(spaces.data().as_ref(), &path.cc);
        Ok(assembler.assemble::<OneRttHeader, _, _, _>(
            spaces.data().as_ref(),
            (ack_package, &path.heartbeat),
            buffer,
        )?)
    }

    pub async fn burst<'b, I, Z, H, O>(
        &self,
        data_sources: &mut (I, Z, H, O),
        buffers: &'b mut Vec<Vec<u8>>,
    ) -> Result<Vec<io::IoSlice<'b>>, BurstError>
    where
        I: PackageIntoSpacePacketWriter<InitialHeader, InitialSpace>,
        Z: PackageIntoSpacePacketWriter<ZeroRttHeader, DataSpace>,
        H: PackageIntoSpacePacketWriter<HandshakeHeader, HandshakeSpace>,
        O: PackageIntoSpacePacketWriter<OneRttHeader, DataSpace>,
    {
        let Ok(max_segments) = self.path.interface.max_segments() else {
            return Err(BurstError::PathDeactived);
        };
        let Ok(max_segment_size) = self.path.interface.max_segment_size() else {
            return Err(BurstError::PathDeactived);
        };

        if buffers.len() < max_segments {
            buffers.resize_with(max_segments, || vec![0; max_segment_size]);
        }

        let reversed_size = 0; // TODO

        use std::ops::ControlFlow::*;
        let (Break(segemnts_lens) | Continue(segemnts_lens)) = buffers
            .iter_mut()
            .map(move |buffer| {
                if buffer.len() < max_segment_size {
                    buffer.resize(max_segment_size, 0);
                }
                &mut buffer[..max_segment_size]
            })
            .map(|segment| {
                let buffer_size = segment.len().min(self.path.mtu() as _);
                let buffer = &mut segment[..buffer_size];

                self.load_spaces(data_sources, buffer)
                    .map(|pkt_size| {
                        self.path.heartbeat.renew_on_effective_communicated();
                        pkt_size
                    })
                    .or_else(|error| match error {
                        BurstError::Signals(signals) => {
                            self.load_ping(buffer).map_err(|e| match e {
                                BurstError::Signals(s) => BurstError::Signals(signals | s),
                                e @ BurstError::PathDeactived => e,
                            })
                        }
                        e @ BurstError::PathDeactived => Err(e),
                    })
                    .or_else(|error| match error {
                        BurstError::Signals(signals) => {
                            self.load_heartbeat(buffer).map_err(|e| match e {
                                BurstError::Signals(s) => BurstError::Signals(signals | s),
                                e @ BurstError::PathDeactived => e,
                            })
                        }
                        e @ BurstError::PathDeactived => Err(e),
                    })
                    .map(|packet_size| io::IoSlice::new(&buffer[..reversed_size + packet_size]))
            })
            .try_fold(
                Ok(Vec::with_capacity(max_segments)),
                |segments, load_result| match (segments, load_result) {
                    (Ok(segments), Err(signals)) if segments.is_empty() => Break(Err(signals)),
                    (Ok(segments), Err(_signals)) => Break(Ok(segments)),
                    (Ok(mut segments), Ok(segment))
                        if segment.len() < segments.last().copied().unwrap_or_default() =>
                    {
                        segments.push(segment.len());
                        Break(Ok(segments))
                    }
                    (Ok(mut segments), Ok(segment)) => {
                        segments.push(segment.len());
                        Continue(Ok(segments))
                    }
                    (Err(_), _) => unreachable!("segments should not be Err in this context"),
                },
            );

        Ok(segemnts_lens?
            .iter()
            .zip(buffers)
            .map(|(&len, buffer)| io::IoSlice::new(&buffer[..len]))
            .collect())
    }
}
