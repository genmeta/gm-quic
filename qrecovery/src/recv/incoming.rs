use super::recver::{ArcRecver, Recver};
use bytes::Bytes;
use qbase::{
    error::Error as QuicError,
    frame::{ResetStreamFrame, StreamFrame},
};
use std::{
    future::Future,
    io,
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

    pub fn recv_data(&self, stream_frame: StreamFrame, body: Bytes) -> Result<(), QuicError> {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        match inner {
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => {
                    r.recv(stream_frame, body)?;
                }
                Recver::SizeKnown(r) => {
                    r.recv(stream_frame, body)?;
                    if r.is_all_rcvd() {
                        *receiving_state = Recver::DataRecvd(r.make_data_recvd());
                    }
                }
                _ => {
                    println!("ignored stream frame {:?}", stream_frame);
                }
            },
            Err(_) => (),
        }
        Ok(())
    }

    pub fn end(&self, final_size: u64) {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        match inner {
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => {
                    *receiving_state = Recver::SizeKnown(r.determin_size(final_size));
                }
                _ => {
                    println!("there is sth wrong, ignored finish");
                }
            },
            Err(_) => (),
        }
    }

    pub fn recv_reset(&self, reset_frame: ResetStreamFrame) -> Result<(), QuicError> {
        // TODO: ResetStream中还有错误信息，比如http3的错误码，看是否能用到
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        match inner {
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => {
                    let final_size = r.recv_reset(reset_frame)?;
                    *receiving_state = Recver::ResetRecvd(final_size);
                }
                Recver::SizeKnown(r) => {
                    let final_size = r.recv_reset(reset_frame)?;
                    *receiving_state = Recver::ResetRecvd(final_size);
                }
                _ => {
                    unreachable!("there is sth wrong, ignored recv_reset");
                }
            },
            Err(_) => (),
        }
        Ok(())
    }

    pub fn on_conn_error(&self, err: &QuicError) {
        let mut recver = self.0.lock().unwrap();
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
        match inner {
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => r.poll_window_update(cx),
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
    // true means stopped by app.
    // false means it was never stopped until the end.
    type Output = bool;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        match inner {
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => r.poll_stop(cx),
                Recver::SizeKnown(r) => r.poll_stop(cx),
                // Even in the Reset state, it is because the sender's reset was received,
                // not because the receiver actively stopped. The receiver's active stop
                // will not change the state, so it can only receive stop notifications in
                // the Recv/SizeKnown state.
                _ => Poll::Ready(false),
            },
            Err(_) => Poll::Ready(false),
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
