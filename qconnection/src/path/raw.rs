use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use qbase::{
    cid::{ArcCidCell, ConnectionId, MAX_CID_SIZE},
    flow::FlowController,
    frame::{AckFrame, PathChallengeFrame, PathResponseFrame},
    handshake::Handshake,
    streamid::Role::Client,
};
use qcongestion::{
    congestion::{ArcCC, CongestionAlgorithm},
    CongestionControl,
};
use qrecovery::{reliable::ArcReliableFrameDeque, space::Epoch};
use qudp::ArcUsc;
use tokio::time::timeout;

use super::{
    anti_amplifier::{ArcAntiAmplifier, ANTI_FACTOR},
    read::ReadIntoDatagrams,
    util::{RecvBuffer, SendBuffer},
    Pathway, ViaPathway,
};
use crate::connection::{
    transmit::{
        data::DataSpaceReader, handshake::HandshakeSpaceReader, initial::InitialSpaceReader,
    },
    validator::ArcAddrValidator,
};

#[derive(Clone)]
pub struct RawPath {
    pub(super) usc: ArcUsc,
    pub(super) cc: ArcCC,
    pub(super) anti_amplifier: ArcAntiAmplifier<ANTI_FACTOR>,
    pub(super) dcid: ArcCidCell<ArcReliableFrameDeque>,
    pub(super) scid: ConnectionId,
    pub(super) spin: Arc<AtomicBool>,
    pub(super) challenge_sndbuf: SendBuffer<PathChallengeFrame>,
    pub(super) response_sndbuf: SendBuffer<PathResponseFrame>,
    pub(super) response_rcvbuf: RecvBuffer<PathResponseFrame>,
}

impl RawPath {
    pub fn new(usc: ArcUsc, dcid: ArcCidCell<ArcReliableFrameDeque>) -> Self {
        // TODO: 从cid_registry.local 随便选一个能用的
        // 到 1 rtt 空间不再需要
        let scid = ConnectionId::random_gen(MAX_CID_SIZE);

        Self {
            usc,
            dcid,
            scid,
            cc: ArcCC::new(CongestionAlgorithm::Bbr, Duration::from_micros(100)),
            anti_amplifier: ArcAntiAmplifier::<ANTI_FACTOR>::default(),
            spin: Arc::new(AtomicBool::new(false)),
            challenge_sndbuf: SendBuffer::default(),
            response_sndbuf: SendBuffer::default(),
            response_rcvbuf: RecvBuffer::default(),
        }
    }

    pub fn recv_response(&self, frame: PathResponseFrame) {
        self.response_rcvbuf.write(frame);
    }

    /// 收到Challenge，马上响应Response
    pub fn recv_challenge(&self, frame: PathChallengeFrame) {
        self.response_sndbuf.write(frame.into());
    }

    pub fn begin_validation(
        &self,
        handshake: &Handshake<ArcReliableFrameDeque>,
        addr_validator: &ArcAddrValidator,
    ) {
        if !handshake.is_handshake_done() {
            if handshake.role() == Client {
                self.anti_amplifier.grant();
                return;
            }
            tokio::spawn({
                let anti_amplifier = self.anti_amplifier.clone();
                let addr_validator = addr_validator.clone();
                async move {
                    addr_validator.await;
                    anti_amplifier.grant();
                }
            });
            return;
        }
        let anti_amplifier = self.anti_amplifier.clone();
        let challenge_sndbuf = self.challenge_sndbuf.clone();
        let response_rcvbuf = self.response_rcvbuf.clone();
        // THINK: 这里应该只需要一个ArcRtt，并不需congestion controller出面
        let congestion_ctrl = self.cc.clone();
        tokio::spawn(async move {
            let challenge = PathChallengeFrame::random();
            for _ in 0..3 {
                let pto = congestion_ctrl.get_pto_time(Epoch::Data);
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
            // TODO: 告知Path不可用，并通知外部观察者处理该Path
        });
    }

    pub fn begin_sending<G>(&self, pathway: Pathway, flow_ctrl: &FlowController, gen_readers: G)
    where
        G: Fn(&RawPath) -> (InitialSpaceReader, HandshakeSpaceReader, DataSpaceReader),
    {
        let mut usc = self.usc.clone();
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
                if let Some(iovec) = read_into_datagram.read(&mut datagrams).await {
                    let _err = usc.send_via_pathway(&iovec, pathway).await;
                    // TODO: 处理错误
                }
            }
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

    pub fn challenge_sndbuf(&self) -> SendBuffer<PathChallengeFrame> {
        self.challenge_sndbuf.clone()
    }

    pub fn response_sndbuf(&self) -> SendBuffer<PathResponseFrame> {
        self.response_sndbuf.clone()
    }

    /*
    pub(super) fn inactive(&mut self) {
        self.dcid.retire();
        self.response_listner.0.lock().unwrap().inactive();
    }
    */

    pub fn is_inactive(&self) -> bool {
        false
        /*
        let listner = self.response_listner.0.lock().unwrap();
        matches!(*listner, ResponseListener::Inactive)
        */
    }
}
