use std::{
    future::Future,
    io,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use qbase::{
    error::Error as QuicError,
    frame::{ResetStreamFrame, StreamFrame},
};

use super::recver::{ArcRecver, Recver};

#[derive(Debug, Clone)]
pub struct Incoming(ArcRecver);

impl Incoming {
    pub(super) fn new(recver: ArcRecver) -> Self {
        Self(recver)
    }

    pub fn recv_data(&self, stream_frame: &StreamFrame, body: Bytes) -> Result<usize, QuicError> {
        let mut recver = self.0.lock();
        let inner = recver.deref_mut();
        let mut new_data_size = 0;
        if let Ok(receiving_state) = inner {
            match receiving_state {
                Recver::Recv(r) => {
                    new_data_size = r.recv(stream_frame, body)?;
                }
                Recver::SizeKnown(r) => {
                    new_data_size = r.recv(stream_frame, body)?;
                    if r.is_all_rcvd() {
                        *receiving_state = Recver::DataRcvd(r.into());
                    }
                }
                _ => {
                    log::debug!("ignored stream frame {:?}", stream_frame);
                }
            }
        }
        Ok(new_data_size)
    }

    pub fn end(&self, final_size: u64) {
        let mut recver = self.0.lock();
        let inner = recver.deref_mut();
        if let Ok(receiving_state) = inner {
            match receiving_state {
                Recver::Recv(r) => {
                    *receiving_state = Recver::SizeKnown(r.determin_size(final_size));
                }
                _ => {
                    log::debug!("there is sth wrong, ignored finish");
                }
            }
        }
    }

    pub fn recv_reset(&self, reset_frame: &ResetStreamFrame) -> Result<(), QuicError> {
        // TODO: ResetStream中还有错误信息，比如http3的错误码，看是否能用到
        let mut recver = self.0.lock();
        let inner = recver.deref_mut();
        if let Ok(receiving_state) = inner {
            match receiving_state {
                Recver::Recv(r) => {
                    let final_size = r.recv_reset(reset_frame)?;
                    *receiving_state = Recver::ResetRcvd(final_size);
                }
                Recver::SizeKnown(r) => {
                    let final_size = r.recv_reset(reset_frame)?;
                    *receiving_state = Recver::ResetRcvd(final_size);
                }
                _ => {
                    log::error!("there is sth wrong, ignored recv_reset");
                    unreachable!();
                }
            }
        }
        Ok(())
    }

    pub fn on_conn_error(&self, err: &QuicError) {
        let mut recver = self.0.lock();
        let inner = recver.deref_mut();
        match inner {
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => r.wake_all(),
                Recver::SizeKnown(r) => r.wake_all(),
                _ => return,
            },
            Err(_) => return,
        };
        *inner = Err(io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()));
    }

    /// 应用层是否对流写入结束，如果是，那么应要发送STOP_SENDING
    pub fn is_stopped_by_app(&self) -> IsStopped {
        IsStopped(self.0.clone())
    }

    /// 对流控来说，何时发送窗口更新？当连续确认接收数据一半以上时
    pub fn need_update_window(&self) -> UpdateWindow {
        UpdateWindow(self.0.clone())
    }
}

pub struct UpdateWindow(ArcRecver);

impl Future for UpdateWindow {
    type Output = Option<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut recver = self.0.lock();
        let inner = recver.deref_mut();
        match inner {
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => r.poll_update_window(cx),
                // In other states, the window will no longer be updated, so return None
                // to inform the streams controller to stop polling for window updates.
                _ => Poll::Ready(None),
            },
            // No need to listen to window updates if the connection is broken.
            Err(_) => Poll::Ready(None),
        }
    }
}

pub struct IsStopped(ArcRecver);

impl Future for IsStopped {
    // If stopped by the application layer, return the application layer's error code;
    // If not stopped by the application layer, return Pending
    // If it is not stopped by the application layer until the stream ends, return None
    type Output = Option<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut recver = self.0.lock();
        let inner = recver.deref_mut();
        match inner {
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => r.poll_stop(cx),
                Recver::SizeKnown(r) => r.poll_stop(cx),
                // Even in the Reset state, it is because the sender's reset was received,
                // not because the receiver actively stopped. The receiver's active stop
                // will not change the state, so it can only receive stop notifications in
                // the Recv/SizeKnown state.
                _ => Poll::Ready(None),
            },
            Err(_) => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod tests {}
