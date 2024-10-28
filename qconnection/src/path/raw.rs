use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use qbase::{
    cid::{ArcCidCell, ConnectionId},
    flow::FlowController,
    frame::{PathChallengeFrame, PathResponseFrame},
};
use qcongestion::{ArcCC, CongestionAlgorithm, CongestionControl, MayLoss, RetirePktRecord};
use qrecovery::{reliable::ArcReliableFrameDeque, space::Epoch};
use tokio::time::timeout;

use super::{
    anti_amplifier::{ArcAntiAmplifier, ANTI_FACTOR},
    read::ReadIntoDatagrams,
    state::ArcPathState,
    util::{RecvBuffer, SendBuffer},
    Pathway,
};
use crate::{
    conn::transmit::{
        data::DataSpaceReader, handshake::HandshakeSpaceReader, initial::InitialSpaceReader,
    },
    usc::ArcUsc,
};

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
/// [`Paths`]: super::Paths
/// [`SocketAddr`]: core::net::SocketAddr
/// [`router`]: crate::router::Router
/// [`UscRegistry`]: crate::usc::UscRegistry
#[derive(Clone)]
pub struct Path {
    pub anti_amplifier: ArcAntiAmplifier<ANTI_FACTOR>,
    pub cc: ArcCC,
    pub(super) usc: ArcUsc,
    pub(super) dcid: ArcCidCell<ArcReliableFrameDeque>,
    pub(super) scid: ConnectionId,
    pub(super) spin: Arc<AtomicBool>,
    pub(super) challenge_sndbuf: SendBuffer<PathChallengeFrame>,
    pub(super) response_sndbuf: SendBuffer<PathResponseFrame>,
    pub(super) response_rcvbuf: RecvBuffer<PathResponseFrame>,
    pub(super) state: ArcPathState,
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
        loss: [Box<dyn MayLoss>; 3],
        retire: [Box<dyn RetirePktRecord>; 3],
    ) -> Self {
        Self {
            usc,
            dcid: dcid.clone(),
            scid,
            cc: ArcCC::new(
                CongestionAlgorithm::Bbr,
                Duration::from_micros(100),
                loss,
                retire,
            ),
            anti_amplifier: ArcAntiAmplifier::<ANTI_FACTOR>::default(),
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
            send_flow_ctrl: flow_ctrl.sender(),
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
                if let Err(_udp_error) = send_all.await {
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

    /// Get the udp socket controller of the path.
    #[inline]
    pub fn usc(&self) -> &ArcUsc {
        &self.usc
    }
}
