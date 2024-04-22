use super::sender::{ArcSender, Sender};
use std::{
    future::Future,
    ops::{DerefMut, Range},
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Debug)]
pub struct Outgoing(ArcSender);

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

    pub fn ack_recv(&mut self, range: &Range<u64>) {
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
                } else {
                    inner.replace(Sender::DataSent(s));
                }
            }
            // ignore recv
            other => inner.replace(other),
        };
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
            recvd @ (Sender::DataRecvd | Sender::ResetRecvd) => {
                inner.replace(recvd);
            }
            _ => inner.replace(Sender::ResetSent),
        };
    }

    pub fn is_cancelled_by_app(&self) -> OutgoingCancel {
        OutgoingCancel(self.0.clone())
    }
}

pub struct OutgoingCancel(ArcSender);

#[derive(Debug)]
pub enum CancelError {
    ResetRecvd,
    DataRecvd,
}

impl Future for OutgoingCancel {
    type Output = Result<(), CancelError>;

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
                Poll::Ready(Err(CancelError::ResetRecvd))
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
                Poll::Ready(Err(CancelError::DataRecvd))
            }
        }
    }
}
