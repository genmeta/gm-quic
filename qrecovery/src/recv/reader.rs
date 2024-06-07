use super::recver::{ArcRecver, Recver};
use qbase::varint::VARINT_MAX;
use std::{
    io,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};

#[derive(Debug)]
pub struct Reader(ArcRecver);

impl Reader {
    pub(super) fn new(recver: ArcRecver) -> Self {
        Self(recver)
    }

    /// Tell peer to stop sending data with the given error code.
    /// It meaning sending a STOP_SENDING frame to peer.
    pub fn stop(self, error_code: u64) {
        debug_assert!(error_code <= VARINT_MAX);
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        match inner {
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => {
                    r.stop(error_code);
                }
                Recver::SizeKnown(r) => {
                    r.stop(error_code);
                }
                _ => (),
            },
            Err(_) => (),
        }
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        // 能相当清楚地看到应用层读取数据驱动的接收状态演变
        match inner {
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => r.poll_read(cx, buf),
                Recver::SizeKnown(r) => r.poll_read(cx, buf),
                Recver::DataRcvd(r) => {
                    r.poll_read(buf);
                    if r.is_all_read() {
                        *receiving_state = Recver::DataRead;
                    }
                    Poll::Ready(Ok(()))
                }
                Recver::DataRead => Poll::Ready(Ok(())),
                Recver::ResetRcvd(_final_size) => {
                    *receiving_state = Recver::ResetRead;
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "reset by peer",
                    )))
                }
                Recver::ResetRead => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "you know, reset by peer",
                ))),
            },
            Err(e) => Poll::Ready(Err(io::Error::new(e.kind(), e.to_string()))),
        }
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        match inner {
            // strict mode: don't forget to call stop with the error code when an
            // abnormal termination occurs, or it will panic.
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => {
                    assert!(
                        r.is_stopped(),
                        r#"RecvStream in Recv State must be 
                            stopped with error code before dropped!"#
                    )
                }
                Recver::SizeKnown(r) => {
                    assert!(
                        r.is_stopped(),
                        r#"RecvStream in Recv State must be 
                            stopped with error code before dropped!"#
                    )
                }
                _ => (),
            },
            Err(_) => (),
        }
    }
}

#[cfg(test)]
mod tests {}
