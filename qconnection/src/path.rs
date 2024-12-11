use std::sync::Arc;

use dashmap::DashMap;
use deref_derive::{Deref, DerefMut};
use qbase::{
    cid::{ArcCidCell, ConnectionId},
    frame::{PathChallengeFrame, PathResponseFrame},
    Epoch,
};
use qcongestion::{ArcCC, CongestionControl};
use qrecovery::reliable::ArcReliableFrameDeque;
use state::ArcPathState;
use tokio::time::timeout;

mod anti_amplifier;
mod pathway;
mod read;
mod state;
mod util;

use std::sync::atomic::AtomicBool;

pub use anti_amplifier::{ArcAntiAmplifier, DEFAULT_ANTI_FACTOR};
pub use pathway::{Pathway, RelayAddr};
pub use read::ReadIntoDatagrams;
pub use util::{Constraints, RecvBuffer, SendBuffer};

use crate::{
    conn::{transmit::*, FlowController},
    usc::ArcUsc,
};

pub type ArcPath = Arc<Path>;
pub type ArcPaths = Arc<OldPaths>;

/// A single path of a connection.
///
/// This is a path in QUIC, it also corresponds to the real network path([`Pathway`]). Each path is
/// accompanied by a sending task, which will send the data we need to send to the opposite end of
/// the [`Pathway`], which is peer. Read more about sending tasks in [`Path::begin_sending`].
///
/// The path does not have the capability to receive datagrams from the UDP port because multiple
/// paths for multiple connections may all be using the same [`SocketAddr`]. If you want to know how
/// packets are accepted, you can check [`UscRegistry`] and [`Router`].
///
/// When a path is first established, a path verification will be performed, path frames will be
/// sent and received to verify the path. If the path verification fails, the path will be marked
/// as inactive and them automatically removed from the [`Paths`].
///
/// [`SocketAddr`]: core::net::SocketAddr
/// [`router`]: crate::router::Router
/// [`UscRegistry`]: crate::usc::UscRegistry
#[derive(Clone)]
pub struct Path {
    anti_amplifier: ArcAntiAmplifier<DEFAULT_ANTI_FACTOR>,
    cc: ArcCC,
    usc: ArcUsc,
    dcid: ArcCidCell<ArcReliableFrameDeque>,
    scid: ConnectionId,
    spin: Arc<AtomicBool>,
    challenge_sndbuf: SendBuffer<PathChallengeFrame>,
    response_sndbuf: SendBuffer<PathResponseFrame>,
    response_rcvbuf: RecvBuffer<PathResponseFrame>,
    state: ArcPathState,
}

impl Path {
    /// Create a new path.
    ///
    /// The `scid` is the initial source connection id of the connection, the scid is used for
    /// assmebling long header packets.
    ///
    /// The `dcid` is issued by the peer. Correct dcid is needed for the data packets to be received
    /// correctly by the peer. Since the connection is established, the peer will continue to issue
    /// and retire connection IDs. At the same time, QUIC requires different paths to use different
    /// connections id for security reasons. [`ArcCidCell`] is a structure through which the path
    /// can asynchronously obtain an available connection ID.
    ///
    /// `loss` and `retire` are used to feed back the lost packets and the retired packets to the
    /// space. They are arrays, each element corresponds to a space: intiial space, handshake space,
    /// and data space.
    ///
    pub fn new(
        usc: ArcUsc,
        scid: ConnectionId,
        dcid: ArcCidCell<ArcReliableFrameDeque>,
        cc: ArcCC,
    ) -> Self {
        Self {
            usc,
            dcid: dcid.clone(),
            scid,
            cc,
            anti_amplifier: ArcAntiAmplifier::<DEFAULT_ANTI_FACTOR>::default(),
            spin: Arc::new(AtomicBool::new(false)),
            challenge_sndbuf: SendBuffer::default(),
            response_sndbuf: SendBuffer::default(),
            response_rcvbuf: RecvBuffer::default(),
            state: ArcPathState::new(dcid),
        }
    }

    /// Called when a [`PathResponseFrame`] is received.
    pub fn recv_response(&self, frame: PathResponseFrame) {
        self.response_rcvbuf.write(frame);
    }

    /// Called when a [`PathChallengeFrame`] is received.
    pub fn recv_challenge(&self, frame: PathChallengeFrame) {
        self.response_sndbuf.write(frame.into());
    }

    /// Start the [`path verification`] task.
    ///
    /// The path verification task will send a [`PathChallengeFrame`] to the peer, and wait for the
    /// response. If the response is received, the path is verified and the anti-amplifier limit is
    /// grant.
    ///
    /// The validate task will be executed at most 3 times, each time the task will wait for a PTO.
    /// If the response is not received within the PTO, the task will be executed again(send the same
    /// challenge frame). If the response is not received after 3 times, the path verification fails
    /// and the path will be marked as inactive.
    ///
    /// [`path verification`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-path-validation
    pub fn begin_validation(&self) {
        let anti_amplifier = self.anti_amplifier.clone();
        let challenge_sndbuf = self.challenge_sndbuf.clone();
        let response_rcvbuf = self.response_rcvbuf.clone();
        // THINK: 这里应该只需要一个ArcRtt，并不需congestion controller出面
        let congestion_ctrl = self.cc.clone();
        let state = self.state.clone();
        tokio::spawn(async move {
            let challenge = PathChallengeFrame::random();
            for _ in 0..3 {
                let pto = congestion_ctrl.pto_time(Epoch::Data);
                challenge_sndbuf.write(challenge);
                match timeout(pto, response_rcvbuf.receive()).await {
                    Ok(Some(response)) if *response == *challenge => {
                        anti_amplifier.grant();
                        return;
                    }
                    // 外部发生变化，导致路径验证任务作废
                    Ok(None) => return,
                    // 超时或者收到不对的response，按"停-等协议"，继续再发一次Challenge，最多3次
                    _ => continue,
                }
            }
            anti_amplifier.abort();
            state.to_inactive();
        });
    }

    /// Start the sending task of the path.
    ///
    /// The sending task will read data from the space readers and send them to the peer via the
    /// [`Pathway`]. The sending task will continue to run until the path is marked as inactive or
    /// connection is closed.
    ///
    /// While sending, if a UDP error occurs, the path will be marked as inactive and the sending
    /// task will be terminated.
    ///
    /// To know how datagrams are filled, you can check [`ReadIntoDatagrams`], which is used to
    /// read data from the space readers and fill the datagrams. You can also check the space readers
    /// ([`InitialSpaceReader`], [`HandshakeSpaceReader`], [`DataSpaceReader`]) to know how data is
    /// read from the space.
    pub fn begin_sending<G>(&self, pathway: Pathway, flow_ctrl: &FlowController, gen_readers: G)
    where
        G: Fn(&Path) -> (InitialSpaceReader, HandshakeSpaceReader, DataSpaceReader),
    {
        let usc = self.usc.clone();
        let state = self.state.clone();
        let space_readers = gen_readers(self);
        let read_into_datagram = ReadIntoDatagrams {
            scid: self.scid,
            dcid: self.dcid.clone(),
            cc: self.cc.clone(),
            anti_amplifier: self.anti_amplifier.clone(),
            spin: self.spin.clone(),
            flow_ctrl: flow_ctrl.clone(),
            initial_space_reader: space_readers.0,
            handshake_space_reader: space_readers.1,
            data_space_reader: space_readers.2,
        };

        tokio::spawn(async move {
            let mut datagrams = Vec::with_capacity(4);
            loop {
                let io_vecs = tokio::select! {
                    _ = state.has_been_inactivated() => break,
                    io_vecs = read_into_datagram.read(&mut datagrams) => io_vecs,
                };
                let Some(io_vecs) = io_vecs else { break };
                let send_all = usc.send_all_via_pathway(&io_vecs, pathway);
                if let Err(udp_error) = send_all.await {
                    log::warn!(
                        "faild to send datagrams from `{}` to `{}`: {:?}",
                        pathway.local_addr(),
                        pathway.dst_addr(),
                        udp_error
                    );
                    state.to_inactive();
                    break;
                }
            }
        });
    }

    /// Get the buffer that can read the [`PathChallengeFrame`] path wants to send.
    pub fn challenge_sndbuf(&self) -> SendBuffer<PathChallengeFrame> {
        self.challenge_sndbuf.clone()
    }

    /// Get the buffer that can read the [PathResponseFrame] path wants to send.
    pub fn response_sndbuf(&self) -> SendBuffer<PathResponseFrame> {
        self.response_sndbuf.clone()
    }

    /// Sets the receive time to the current instant, and updates the anti-amplifier limit.
    #[inline]
    pub fn on_rcvd(&self, amount: usize) {
        self.anti_amplifier.on_rcvd(amount);
        self.update_recv_time();
    }

    /// Sets the receive time to the current instant.
    #[inline]
    pub fn update_recv_time(&self) {
        self.state.update_recv_time()
    }

    #[inline]
    pub fn cc(&self) -> &ArcCC {
        &self.cc
    }

    /// Get the udp socket controller of the path.
    ///
    /// For send datagrams directly to the peer when the connection is clonsing.
    #[inline]
    pub fn usc(&self) -> &ArcUsc {
        &self.usc
    }

    /// Disable the anti-amplifier.
    ///
    /// This should only been called when the path validate success.
    #[inline]
    pub fn grant_anti_amplifier(&self) {
        self.anti_amplifier.grant();
    }
}

#[derive(Default, Deref, DerefMut)]
pub struct Paths(Arc<DashMap<Pathway, ArcPath>>);

/// The set of all paths of a connection.
///
/// GM-QUIC supports multiple paths for a connection, each path corresponds to a [`Pathway`].
///
/// The main purpose of this structure is to manage all paths of connections. When other components
/// need to obtain a path, they can call [`Paths::get_or_create`] to get a existing path or create a
/// new path.
///
/// This structure is also responsible for automatically removing a path from the set when it becomes
/// inactive and terminating a connection when no path is available.
#[derive(Deref, DerefMut)]
pub struct OldPaths {
    #[deref]
    map: DashMap<Pathway, ArcPath>,
    creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>,
    on_no_path: Arc<dyn Fn() + Send + Sync + 'static>,
}

impl OldPaths {
    /// Create a new [`Paths`].
    ///
    /// There are two parameters:
    /// - `creator`:  When a path is obtained, but it does not exist, this function will be used to
    ///    create the path. The created paths will be automatically added to the collection and managed.
    ///
    /// - `on_no_path`: A function that will be called when there is no path in the set, this usually
    ///    means that the connection is no longer available. This function can set a connection error
    ///    and directly terminate the connection.
    pub fn new(
        creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>,
        on_no_path: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> Self {
        Self {
            map: DashMap::new(),
            on_no_path,
            creator,
        }
    }

    /// Get a path from the set, if the path does not exist, create a new path.
    ///
    /// The method used to create [`ArcPath`] is specified when creating [`Paths`], you can read
    /// [`Paths::new`] for more information.
    ///
    /// When a path is created, a task will be started to monitor the path. When the path is inactive,
    /// the path will be removed from the set. If there are no paths in the set, the function specified
    /// by `on_no_path`(read [`Paths::new`]) will be called.
    pub fn get_or_create(&self, pathway: Pathway, usc: ArcUsc) -> ArcPath {
        let pathes = self.map.clone();
        let on_no_path = self.on_no_path.clone();

        self.map
            .entry(pathway)
            .or_insert_with(|| {
                let path = (self.creator)(pathway, usc);
                let state = path.state.clone();
                tokio::spawn({
                    let state = state.clone();
                    let cc = path.cc().clone();
                    async move {
                        // TOOD: optimize this
                        loop {
                            tokio::select! {
                                _ = state.has_been_inactivated() => break,
                                _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => cc.do_tick(),
                            }
                        }
                        pathes.remove(&pathway);
                        if pathes.is_empty() {
                            (on_no_path)();
                        }
                    }
                });
                path
            })
            .value()
            .clone()
    }
}
