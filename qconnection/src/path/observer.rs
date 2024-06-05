use qcongestion::{congestion::Epoch, ObserveAck, ObserveLoss, SlideWindow};
use qrecovery::rcvdpkt::{ArcRcvdPktRecords, ArcRcvdPktRecordsWriter};
use tokio::sync::mpsc;

pub struct AckObserverGuard<'a>(ArcRcvdPktRecordsWriter<'a>);

impl SlideWindow for AckObserverGuard<'_> {
    fn inactivate(&mut self, idx: u64) {
        self.0.inactivate(idx)
    }
}

/// Because ArcRcvdPktRecords is too simple, there's no need to use a queue.
pub struct AckObserver([ArcRcvdPktRecords; 3]);

impl AckObserver {
    pub fn new() -> Self {
        todo!("根据3大space的收包记录来创建")
    }
}

impl ObserveAck for AckObserver {
    type Guard<'a> = AckObserverGuard<'a>;

    fn guard(&self, space: Epoch) -> Self::Guard<'_> {
        AckObserverGuard(self.0[space].write())
    }
}

pub struct LossObserver([mpsc::UnboundedSender<u64>; 3]);

impl LossObserver {
    pub fn new(channels: [mpsc::UnboundedSender<u64>; 3]) -> Self {
        Self(channels)
    }
}

impl ObserveLoss for LossObserver {
    fn may_loss_pkt(&self, space: Epoch, pn: u64) {
        let _ = self.0[space].send(pn);
    }
}

#[cfg(test)]
mod tests {}
