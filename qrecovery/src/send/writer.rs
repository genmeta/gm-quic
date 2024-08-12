use std::{
    io,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::AsyncWrite;

use super::sender::{ArcSender, Sender};

#[derive(Debug)]
pub struct Writer(pub(super) ArcSender);

impl AsyncWrite for Writer {
    /// 往sndbuf里面写数据，直到写满MAX_STREAM_DATA，等通告窗口更新再写
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state {
                Sender::Ready(s) => s.poll_write(cx, buf),
                Sender::Sending(s) => s.poll_write(cx, buf),
                Sender::DataSent(_) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "all data has been written",
                ))),
                Sender::DataRcvd => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "all data has been received",
                ))),
                Sender::ResetSent(_) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "reset by local",
                ))),
                Sender::ResetRcvd => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "reset msg has been received by peer",
                ))),
            },
            Err(e) => Poll::Ready(Err(io::Error::new(e.kind(), e.to_string()))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state {
                Sender::Ready(s) => s.poll_flush(cx),
                Sender::Sending(s) => s.poll_flush(cx),
                Sender::DataSent(s) => {
                    let result = s.poll_flush(cx);
                    if result.is_ready() {
                        *sending_state = Sender::DataRcvd
                    }
                    result
                }
                Sender::DataRcvd => Poll::Ready(Ok(())),
                Sender::ResetSent(_) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "reset by local",
                ))),
                Sender::ResetRcvd => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "reset msg has been received by peer",
                ))),
            },
            Err(e) => Poll::Ready(Err(io::Error::new(e.kind(), e.to_string()))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state {
                Sender::Ready(s) => {
                    // 鉴于Ready是尚未分配StreamId的，所以还不具备直接变成DataSent资格
                    // THINK: 如果将来实现的Sender，确实不需要StreamId选项，那可以直接
                    // 转化成DataSent
                    s.poll_shutdown(cx)
                }
                Sender::Sending(s) => {
                    let result = s.poll_shutdown(cx);
                    match &result {
                        Poll::Pending => *sending_state = Sender::DataSent(s.into()),
                        Poll::Ready(_) => *sending_state = Sender::DataRcvd,
                    }
                    // 有可能是Poll::Pending，也有可能是已经发送完数据的Poll::Ready
                    result
                }
                Sender::DataSent(s) => {
                    let result = s.poll_shutdown(cx);
                    // 有一种复杂的情况，就是在DataSent途中，对方发来了STOP_SENDING，我方需立即
                    // reset停止发送，此时状态也轮转到ResetSent中，相当于被动reset，再次唤醒该
                    // poll任务，则会进到ResetSent或者ResetRcvd中poll，得到的将是BrokenPipe错误
                    if result.is_ready() {
                        *sending_state = Sender::DataRcvd;
                    }
                    result
                }
                Sender::DataRcvd => Poll::Ready(Ok(())),
                Sender::ResetSent(_) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "reset by local",
                ))),
                Sender::ResetRcvd => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "reset msg has been received by peer",
                ))),
            },
            Err(e) => Poll::Ready(Err(io::Error::new(e.kind(), e.to_string()))),
        }
    }
}

impl Writer {
    pub fn cancel(self, err_code: u64) {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state {
                Sender::Ready(s) => {
                    s.cancel(err_code);
                }
                Sender::Sending(s) => {
                    s.cancel(err_code);
                }
                Sender::DataSent(s) => {
                    s.cancel(err_code);
                }
                _ => (),
            },
            Err(_) => (),
        };
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            // strict mode: don't forget to call cancel with the error code when an
            // abnormal termination occurs, or it will panic.
            Ok(sending_state) => match sending_state {
                Sender::Ready(s) => {
                    assert!(
                        s.is_cancelled(),
                        "SendingStream in Ready State must be 
                            cancelled with error code before dropped!"
                    );
                }
                Sender::Sending(s) => {
                    assert!(
                        s.is_cancelled(),
                        "SendingStream in Sending State must be 
                            cancelled with error code before dropped!"
                    );
                }
                Sender::DataSent(s) => {
                    assert!(
                        s.is_cancelled(),
                        "SendingStream in DataSent State must be 
                            cancelled with error code before dropped!"
                    );
                }
                _ => (),
            },
            Err(_) => (),
        };
    }
}

#[cfg(test)]
mod tests {}
