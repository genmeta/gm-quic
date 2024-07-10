use qcongestion::{
    congestion::Epoch, ObserveAck, ObserveAntiAmplification, ObserveHandshake, ObserveLoss,
    ObservePto, SlideWindow,
};
use qrecovery::reliable::rcvdpkt::{ArcRcvdPktRecords, ArcRcvdPktRecordsWriter};
use tokio::sync::mpsc;

use super::{anti_amplifier::ANTI_FACTOR, ArcAntiAmplifier};
use crate::connection::state::{ArcConnectionState, ConnectionState};

pub struct AckObserverGuard<'a>(ArcRcvdPktRecordsWriter<'a>);

impl SlideWindow for AckObserverGuard<'_> {
    fn inactivate(&mut self, idx: u64) {
        self.0.inactivate(idx)
    }
}

/// Because ArcRcvdPktRecords is too simple, there's no need to use a queue.
#[derive(Debug, Clone)]
pub struct AckObserver([ArcRcvdPktRecords; 3]);

impl AckObserver {
    pub fn new(records: [ArcRcvdPktRecords; 3]) -> Self {
        Self(records)
    }
}

impl ObserveAck for AckObserver {
    type Guard<'a> = AckObserverGuard<'a>;

    fn ack_guard(&self, space: Epoch) -> Self::Guard<'_> {
        AckObserverGuard(self.0[space].write())
    }
}

#[derive(Debug, Clone)]
pub struct LossObserver([mpsc::UnboundedSender<u64>; 3]);

impl LossObserver {
    // 它是生产者，所以应该返回接收器
    pub fn new() -> (Self, [mpsc::UnboundedReceiver<u64>; 3]) {
        let (tx0, rx0) = mpsc::unbounded_channel();
        let (tx1, rx1) = mpsc::unbounded_channel();
        let (tx2, rx2) = mpsc::unbounded_channel();
        (Self([tx0, tx1, tx2]), [rx0, rx1, rx2])
    }
}

impl ObserveLoss for LossObserver {
    fn may_loss_pkt(&self, space: Epoch, pn: u64) {
        let _ = self.0[space].send(pn);
    }
}

#[derive(Debug, Clone)]
pub struct HandShakeObserver(ArcConnectionState);

impl HandShakeObserver {
    pub fn new(state: ArcConnectionState) -> Self {
        Self(state)
    }
}

impl ObserveHandshake for HandShakeObserver {
    fn is_handshake_done(&self) -> bool {
        self.0.get_state() >= ConnectionState::HandshakeDone
    }

    fn has_handshake_keys(&self) -> bool {
        self.0.get_state() >= ConnectionState::Handshaking
    }
}

#[derive(Debug, Clone)]
pub struct PtoObserver([mpsc::UnboundedSender<()>; 3]);

impl PtoObserver {
    // 它是生产者，所以应该返回接收器
    pub fn new() -> (Self, [mpsc::UnboundedReceiver<()>; 3]) {
        let (tx0, rx0) = mpsc::unbounded_channel();
        let (tx1, rx1) = mpsc::unbounded_channel();
        let (tx2, rx2) = mpsc::unbounded_channel();
        (Self([tx0, tx1, tx2]), [rx0, rx1, rx2])
    }
}

impl ObservePto for PtoObserver {
    fn probe_timeout(&self, space: Epoch) {
        let _ = self.0[space].send(());
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionObserver {
    pub handshake_observer: HandShakeObserver,
    pub ack_observer: AckObserver,
    pub loss_observer: LossObserver,
    pub pto_observer: PtoObserver,
}

impl ObserveAck for ConnectionObserver {
    type Guard<'a> = AckObserverGuard<'a>;

    fn ack_guard(&self, space: Epoch) -> Self::Guard<'_> {
        self.ack_observer.ack_guard(space)
    }
}

impl ObserveLoss for ConnectionObserver {
    fn may_loss_pkt(&self, space: Epoch, pn: u64) {
        self.loss_observer.may_loss_pkt(space, pn)
    }
}

impl ObservePto for ConnectionObserver {
    fn probe_timeout(&self, space: Epoch) {
        self.pto_observer.probe_timeout(space)
    }
}

impl ObserveHandshake for ConnectionObserver {
    fn is_handshake_done(&self) -> bool {
        self.handshake_observer.is_handshake_done()
    }

    fn has_handshake_keys(&self) -> bool {
        self.handshake_observer.has_handshake_keys()
    }
}

pub struct PathObserver(ArcAntiAmplifier<ANTI_FACTOR>);

impl PathObserver {
    pub fn new(anti_amplifier: ArcAntiAmplifier<ANTI_FACTOR>) -> Self {
        Self(anti_amplifier)
    }
}
impl ObserveAntiAmplification for PathObserver {
    fn is_anti_amplification(&self) -> bool {
        self.0.is_ready()
    }
}
#[cfg(test)]
mod tests {}
