use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use qbase::{
    cid::{ArcCidCell, ConnectionId, MAX_CID_SIZE},
    frame::{AckFrame, PathChallengeFrame, PathResponseFrame},
};
use qcongestion::{
    congestion::{ArcCC, CongestionAlgorithm},
    CongestionControl,
};
use qrecovery::space::Epoch;
use qudp::ArcUsc;
use tokio::time::timeout;

use super::{
    anti_amplifier::{ArcAntiAmplifier, ANTI_FACTOR},
    util::{RecvBuffer, SendBuffer},
};
use crate::connection::raw::RawConnection;

#[derive(Clone)]
pub struct RawPath {
    pub(super) usc: ArcUsc,
    pub(super) cc: ArcCC,
    pub(super) anti_amplifier: ArcAntiAmplifier<ANTI_FACTOR>,
    pub(super) dcid: ArcCidCell,
    pub(super) scid: ConnectionId,
    pub(super) spin: Arc<AtomicBool>,
    pub(super) challenge_sndbuf: SendBuffer<PathChallengeFrame>,
    pub(super) response_sndbuf: SendBuffer<PathResponseFrame>,
    pub(super) response_rcvbuf: RecvBuffer<PathResponseFrame>,
}

impl RawPath {
    pub(super) fn new(usc: ArcUsc, connection: &RawConnection) -> Self {
        let cc = ArcCC::new(CongestionAlgorithm::Bbr, Duration::from_micros(100));
        let anti_amplifier = ArcAntiAmplifier::<ANTI_FACTOR>::default();

        let dcid = connection.cid_registry.remote.apply_cid();

        // TODO: 从cid_registry.local 随便选一个能用的
        // 到 1 rtt 空间不再需要
        let scid = ConnectionId::random_gen(MAX_CID_SIZE);

        Self {
            usc,
            cc,
            anti_amplifier,
            dcid,
            scid,
            spin: Arc::new(AtomicBool::new(false)),
            challenge_sndbuf: SendBuffer::default(),
            response_sndbuf: SendBuffer::default(),
            response_rcvbuf: RecvBuffer::default(),
        }
    }

    pub fn recv_response(&mut self, frame: PathResponseFrame) {
        self.response_rcvbuf.write(frame);
    }

    /// 收到Challenge，马上响应Response
    pub fn recv_challenge(&mut self, frame: PathChallengeFrame) {
        self.response_sndbuf.write(frame.into());
    }

    pub fn begin_path_validation(&self) {
        let anti_amplifier = self.anti_amplifier.clone();
        let challenge_sndbuf = self.challenge_sndbuf.clone();
        let response_rcvbuf = self.response_rcvbuf.clone();
        // THINK: 这里应该只需要一个ArcRtt，并不需congestion controller出面
        let congestion_ctrl = self.cc.clone();
        tokio::spawn(async move {
            let challenge = PathChallengeFrame::random();
            for _ in 0..3 {
                let pto = congestion_ctrl.get_pto_time(Epoch::Data);
                challenge_sndbuf.write(challenge.clone());
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
            // TODO: 告知Path不可用，并通知外部观察者处理该Path
        });
    }

    pub fn pto_time(&self) -> Duration {
        self.cc.get_pto_time(Epoch::Data)
    }

    pub fn on_ack(&self, epoch: Epoch, ack: &AckFrame) {
        self.cc.on_ack(epoch, ack);
    }

    pub fn on_recv_pkt(&self, epoch: Epoch, pn: u64, is_ack_eliciting: bool) {
        self.cc.on_recv_pkt(epoch, pn, is_ack_eliciting);
    }

    /*
    pub(super) fn inactive(&mut self) {
        self.dcid.retire();
        self.response_listner.0.lock().unwrap().inactive();
    }
    */

    pub(super) fn is_inactive(&self) -> bool {
        false
        /*
        let listner = self.response_listner.0.lock().unwrap();
        matches!(*listner, ResponseListener::Inactive)
        */
    }
}
