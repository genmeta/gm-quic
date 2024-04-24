use super::sender::{ArcSender, Sender};
use std::{
    future::Future,
    ops::{DerefMut, Range},
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Debug, Clone)]
pub struct Outgoing(pub(super) ArcSender);

impl Outgoing {
    pub fn update_window(&mut self, max_data_size: u64) {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner.take() {
            Sender::Sending(mut s) => {
                s.update_window(max_data_size);
                inner.replace(Sender::Sending(s));
            }
            other => inner.replace(other),
        }
    }

    pub fn pick_up(&mut self) -> Option<(u64, &[u8])> {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner.take() {
            Sender::Ready(s) => {
                inner.replace(Sender::Ready(s));
            }
            Sender::Sending(s) => {
                inner.replace(Sender::Sending(s));
            }
            Sender::DataSent(s) => {
                inner.replace(Sender::DataSent(s));
            }
            other => inner.replace(other),
        };
        todo!("正常有数据，还是没数据？没数据是因为结束，还是被流控，还是空闲？话要说清楚")
    }

    pub fn ack_recv(&mut self, range: &Range<u64>) -> bool {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner.take() {
            Sender::Ready(_) => {
                unreachable!("never send data before recv data");
            }
            Sender::Sending(mut s) => {
                s.ack_recv(range);
                inner.replace(Sender::Sending(s));
            }
            Sender::DataSent(mut s) => {
                s.ack_recv(range);
                if s.is_all_recvd() {
                    inner.replace(Sender::DataRecvd);
                    return true;
                } else {
                    inner.replace(Sender::DataSent(s));
                }
            }
            // ignore recv
            other => inner.replace(other),
        };
        return false;
    }

    pub fn may_loss(&mut self, range: &Range<u64>) {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner.take() {
            Sender::Ready(_) => {
                unreachable!("never send data before recv data");
            }
            Sender::Sending(mut s) => {
                s.may_loss(range);
                inner.replace(Sender::Sending(s));
            }
            Sender::DataSent(mut s) => {
                s.may_loss(range);
                inner.replace(Sender::DataSent(s));
            }
            // ignore loss
            other => inner.replace(other),
        };
    }

    // 被动reset
    pub fn stop(&mut self) {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner.take() {
            Sender::Ready(_) => {
                unreachable!("never send data before recv data");
            }
            Sender::DataSent(s) => {
                s.stop();
                inner.replace(Sender::ResetSent);
            }
            Sender::Sending(s) => {
                s.stop();
                inner.replace(Sender::ResetSent);
            }
            recvd @ (Sender::DataRecvd | Sender::ResetSent | Sender::ResetRecvd) => {
                inner.replace(recvd);
            }
        };
    }

    pub fn ack_reset(&mut self) {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner.take() {
            Sender::ResetSent | Sender::ResetRecvd => {
                inner.replace(Sender::ResetRecvd);
            }
            _ => {
                unreachable!(
                    "If no RESET_STREAM has been sent, how can there be a received acknowledgment?"
                );
            }
        };
    }

    pub fn is_cancelled_by_app(&self) -> IsCancelled {
        IsCancelled(self.0.clone())
    }
}

pub struct IsCancelled(ArcSender);

#[derive(Debug)]
pub enum CancelTooLate {
    ResetRecvd,
    DataRecvd,
}

impl Future for IsCancelled {
    type Output = Result<(), CancelTooLate>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner.take() {
            Sender::ResetSent => {
                inner.replace(Sender::ResetSent);
                Poll::Ready(Ok(()))
            }
            Sender::ResetRecvd => {
                inner.replace(Sender::ResetRecvd);
                Poll::Ready(Err(CancelTooLate::ResetRecvd))
            }
            Sender::Ready(mut s) => {
                s.poll_cancel(cx);
                inner.replace(Sender::Ready(s));
                Poll::Pending
            }
            Sender::Sending(mut s) => {
                s.poll_cancel(cx);
                inner.replace(Sender::Sending(s));
                Poll::Pending
            }
            Sender::DataSent(mut s) => {
                s.poll_cancel(cx);
                inner.replace(Sender::DataSent(s));
                Poll::Pending
            }
            Sender::DataRecvd => {
                inner.replace(Sender::DataRecvd);
                Poll::Ready(Err(CancelTooLate::DataRecvd))
            }
        }
    }
}
