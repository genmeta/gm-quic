use super::recver::{ArcRecver, Recver};
use bytes::Bytes;
use qbase::{
    error::Error,
    frame::{ResetStreamFrame, StreamFrame},
};
use std::{
    future::Future,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Debug, Clone)]
pub struct Incoming(ArcRecver);

impl Incoming {
    pub(super) fn new(recver: ArcRecver) -> Self {
        Self(recver)
    }

    pub fn recv(&self, stream_frame: StreamFrame, body: Bytes) -> Result<(), Error> {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        match inner.take() {
            Recver::Recv(mut r) => {
                r.recv(stream_frame, body)?;
                inner.replace(Recver::Recv(r));
            }
            Recver::SizeKnown(mut r) => {
                r.recv(stream_frame, body)?;
                if r.is_all_rcvd() {
                    inner.replace(Recver::DataRecvd(r.data_recvd()));
                } else {
                    inner.replace(Recver::SizeKnown(r));
                }
            }
            other => {
                println!("ignored stream frame {:?}", stream_frame);
                inner.replace(other);
            }
        }
        Ok(())
    }

    pub fn end(&self, final_size: u64) {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        match inner.take() {
            Recver::Recv(r) => {
                inner.replace(Recver::SizeKnown(r.determin_size(final_size)));
            }
            other => {
                println!("there is sth wrong, ignored finish");
                inner.replace(other);
            }
        }
    }

    pub fn recv_reset(&self, reset_frame: ResetStreamFrame) -> Result<(), Error> {
        // TODO: ResetStream中还有错误信息，比如http3的错误码，看是否能用到
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        match inner.take() {
            Recver::Recv(r) => {
                let final_size = r.recv_reset(reset_frame)?;
                inner.replace(Recver::ResetRecvd(final_size));
            }
            Recver::SizeKnown(r) => {
                let final_size = r.recv_reset(reset_frame)?;
                inner.replace(Recver::ResetRecvd(final_size));
            }
            other => {
                println!("there is sth wrong, ignored recv_reset");
                inner.replace(other);
            }
        }
        Ok(())
    }

    /// 应用层是否对流写入结束，如果是，那么应要发送STOP_SENDING
    pub fn is_stopped_by_app(&self) -> IsStopped {
        IsStopped(self.0.clone())
    }

    /// 对流控来说，何时发送窗口更新？当连续确认接收数据一半以上时
    pub fn need_window_update(&self) -> WindowUpdate {
        WindowUpdate(self.0.clone())
    }
}

pub struct WindowUpdate(ArcRecver);

impl Future for WindowUpdate {
    type Output = Option<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        match inner.take() {
            Recver::Recv(mut r) => {
                let result = r.poll_window_update(cx);
                inner.replace(Recver::Recv(r));
                result
            }
            other => {
                inner.replace(other);
                // In other states, the window will no longer be updated, so return None
                // to inform the streams controller to stop polling for window updates.
                Poll::Ready(None)
            }
        }
    }
}

pub struct IsStopped(ArcRecver);

impl Future for IsStopped {
    // true means stopped by app.
    // false means it was never stopped until the end.
    type Output = bool;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        match inner.take() {
            Recver::Recv(mut r) => {
                let result = r.poll_stop(cx);
                inner.replace(Recver::Recv(r));
                result
            }
            Recver::SizeKnown(mut r) => {
                let result = r.poll_stop(cx);
                inner.replace(Recver::SizeKnown(r));
                result
            }
            finished @ (Recver::DataRead | Recver::DataRecvd(_)) => {
                inner.replace(finished);
                Poll::Ready(false)
            }
            reset @ (Recver::ResetRead | Recver::ResetRecvd(_)) => {
                inner.replace(reset);
                // Even in the Reset state, it is because the sender's reset was received,
                // not because the receiver actively stopped. The receiver's active stop
                // will not change the state, so it can only receive stop notifications in
                // the Recv/SizeKnown state.
                Poll::Ready(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
