use super::recver::{ArcRecver, Recver};
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
}

// TODO: 还要实现abort
// TODO: Reader的drop，意味着自动abort

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        // 能相当清楚地看到应用层读取数据驱动的接收状态演变
        match inner.take() {
            Recver::Recv(mut r) => {
                let result = r.poll_read(cx, buf);
                inner.replace(Recver::Recv(r));
                result
            }
            Recver::SizeKnown(mut r) => {
                let result = r.poll_read(cx, buf);
                inner.replace(Recver::SizeKnown(r));
                result
            }
            Recver::DataRecvd(mut r) => {
                r.poll_read(buf);
                if r.is_all_read() {
                    inner.replace(Recver::DataRead);
                } else {
                    inner.replace(Recver::DataRecvd(r));
                }
                Poll::Ready(Ok(()))
            }
            Recver::DataRead => Poll::Ready(Ok(())),
            Recver::ResetRecvd(_final_size) => {
                inner.replace(Recver::ResetRead);
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
            Recver::ResetRead => {
                inner.replace(Recver::ResetRead);
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
        }
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        match inner.take() {
            Recver::Recv(mut r) => {
                r.abort();
                inner.replace(Recver::Recv(r));
            }
            Recver::SizeKnown(mut r) => {
                r.abort();
                inner.replace(Recver::SizeKnown(r));
            }
            other => {
                inner.replace(other);
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
