use std::{
    io,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

use qbase::streamid::StreamId;
use tokio::io::AsyncWrite;

use super::sender::{ArcSender, Sender};

/// The writer part of a QUIC stream.
///
/// This struct implements the [`AsyncWrite`] trait, allowing you to write data to the stream.
///
/// A QUIC stream is *reliable*, *ordered*, and *flow-controlled*.
///
/// The amount of data that can be sent is limited by flow control. The [`write`] call will be blocked
/// if the amount of data written reaches the flow control limit.
///
/// The [`flush`] and [`shutdown`] calls will be blocked until all data written to [`Writer`] has
/// been sent and acknowledged by the peer.
///
/// # Note
///
/// The stream must be cancelled or shutdowned before the [`Writer`] dropped.
///
/// Call [`shutdown`] means that there are no more new data will been written to the stream. If all
/// of the data written to the stream has been sent and acknowledged by the peer, the stream will be
/// `closed`, and the [`shutdown`] call complete with `Ok(())`.
///
/// Alternatively, if the operations on the [`Writer`] result an error, its indicates that the stream
/// has been cancelled in other reason, such as connection closed, the peer acked local to stop sending.
///
/// You can call [`cancel`] to `cancel` the stream with the given error code, The [`Writer`] will be
/// consumed, and neither new data nor lost data will be sent anymore.
///
/// # Example
///
/// The [`Writer`] is created by the `open_bi_stream`, `open_uni_stream`, or `accept_bi_stream` methods of
/// `QuicConnection` (in the `gm-quic` crate).
///
/// The following example demonstrates how to read and write data on a QUIC stream.
///
/// ```rust, ignore
/// # use tokio::io::{AsyncWriteExt, AsyncReadExt};
/// # async fn example() -> std::io::Result<()> {
/// let (reader, writer) = quic_connection.open_bi_stream().await?;
///
/// writer.write_all(b"GET README.md\r\n").await?;
/// writer.shutdown().await?;
///
/// let mut response = String::new();
/// let n = reader.read_to_string(&mut response).await?;
/// println!("Response {} bytes: {}", n, response);
/// Ok(())
/// # }
/// ```
///
/// [`write`]: tokio::io::AsyncWriteExt::write
/// [`flush`]: tokio::io::AsyncWriteExt::flush
/// [`shutdown`]: tokio::io::AsyncWriteExt::shutdown
/// [`cancel`]: Writer::cancel
/// [`STOP_SENDING frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames
#[derive(Debug)]
pub struct Writer(pub(crate) ArcSender);

impl Writer {
    /// Cancels the stream with the given error code(reset the stream).
    ///
    /// If all data has been sent and acknowledged by the peer(the stream has closed), or the stream
    /// has been reset, this method will do nothing.
    ///
    /// Otherwise, a [`RESET_STREAM frame`] will be sent to the peer, and the stream will be reset,
    /// neither new data nor lost data will be sent.
    ///
    /// [`RESET_STREAM frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
    pub fn cancel(self, err_code: u64) {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::Ready(s) => s.cancel(err_code),
                Sender::Sending(s) => s.cancel(err_code),
                Sender::DataSent(s) => s.cancel(err_code),
                _ => (),
            }
        };
    }

    /// Returns the stream ID of the stream.
    pub fn stream_id(&self) -> StreamId {
        self.0.sid()
    }
}

impl AsyncWrite for Writer {
    /// 往sndbuf里面写数据，直到写满MAX_STREAM_DATA，等通告窗口更新再写
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut sender = self.0.sender();
        let sending_state = sender.as_mut().map_err(|e| e.clone())?;
        match sending_state {
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
            Sender::ResetSent(reset) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, *reset)))
            }
            Sender::ResetRcvd(reset) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, *reset)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut sender = self.0.sender();
        let sending_state = sender.as_mut().map_err(|e| e.clone())?;
        match sending_state {
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
            Sender::ResetSent(reset) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, *reset)))
            }
            Sender::ResetRcvd(reset) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, *reset)))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut sender = self.0.sender();
        let sending_state = sender.as_mut().map_err(|e| e.clone())?;
        match sending_state {
            Sender::Ready(s) => {
                if let Err(e) = s.shutdown(cx) {
                    Poll::Ready(Err(e))
                } else {
                    *sending_state = Sender::DataSent(s.into());
                    Poll::Pending
                }
            }
            Sender::Sending(s) => {
                if let Err(e) = s.shutdown(cx) {
                    Poll::Ready(Err(e))
                } else {
                    *sending_state = Sender::DataSent(s.into());
                    Poll::Pending
                }
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
            Sender::ResetSent(reset) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, *reset)))
            }
            Sender::ResetRcvd(reset) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, *reset)))
            }
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
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
            }
        };
    }
}

#[cfg(test)]
mod tests {}
