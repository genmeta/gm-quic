use std::{
    ops::Deref,
    sync::{atomic::AtomicBool, Arc},
    time::{self, Duration},
};

use qbase::{
    cid::{ArcCidCell, ConnectionId},
    flow::FlowController,
    frame::{PathChallengeFrame, PathResponseFrame},
};
use qcongestion::{ArcCC, CongestionAlgorithm, CongestionControl, MayLoss, RetirePktRecord};
use qrecovery::{reliable::ArcReliableFrameDeque, space::Epoch};
use qudp::ArcUsc;
use tokio::time::timeout;

use super::{
    anti_amplifier::{ArcAntiAmplifier, ANTI_FACTOR},
    read::ReadIntoDatagrams,
    state::ArcPathState,
    util::{RecvBuffer, SendBuffer},
    Pathway, ViaPathWayExt,
};
use crate::connection::transmit::{
    data::DataSpaceReader, handshake::HandshakeSpaceReader, initial::InitialSpaceReader,
};

#[derive(Clone)]
pub struct RawPath {
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

impl RawPath {
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

    pub fn recv_response(&self, frame: PathResponseFrame) {
        self.response_rcvbuf.write(frame);
    }

    /// 收到Challenge，马上响应Response
    pub fn recv_challenge(&self, frame: PathChallengeFrame) {
        self.response_sndbuf.write(frame.into());
    }

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

    pub fn begin_sending<G>(&self, pathway: Pathway, flow_ctrl: &FlowController, gen_readers: G)
    where
        G: Fn(&RawPath) -> (InitialSpaceReader, HandshakeSpaceReader, DataSpaceReader),
    {
        let mut usc = self.usc.clone();
        let state = self.state.clone();
        let space_readers = gen_readers(self);
        let read_into_datagram = ReadIntoDatagrams {
            scid: self.scid,
            dcid: self.dcid.clone(),
            cc: self.cc.clone(),
            anti_amplifier: self.anti_amplifier.clone(),
            spin: self.spin.clone(),
            send_flow_ctrl: flow_ctrl.sender(),
            initial_space_reader: space_readers.0.clone(),
            handshake_space_reader: space_readers.1.clone(),
            data_space_reader: space_readers.2.clone(),
        };

        tokio::spawn(async move {
            let mut datagrams = Vec::with_capacity(4);

            while let Some(iovec) = read_into_datagram.read(&mut datagrams).await {
                let send_result = usc.send_all_via_pathway(&iovec, pathway).await;
                if send_result.is_err() {
                    state.to_inactive();
                    return;
                }
            }
        });
    }

    pub fn challenge_sndbuf(&self) -> SendBuffer<PathChallengeFrame> {
        self.challenge_sndbuf.clone()
    }

    pub fn response_sndbuf(&self) -> SendBuffer<PathResponseFrame> {
        self.response_sndbuf.clone()
    }

    /// Sets the receive time to the current instant.
    pub fn update_recv_time(&self) {
        *self.state.deref().lock().unwrap() = time::Instant::now();
    }
}
