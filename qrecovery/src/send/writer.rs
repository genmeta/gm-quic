use std::{
    io,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

use qbase::frame::{ResetStreamFrame, SendFrame};
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
pub struct Writer<TX>(pub(crate) ArcSender<TX>);

impl<TX> Writer<TX>
where
    TX: SendFrame<ResetStreamFrame>,
{
    /// Cancels the stream with the given error code(reset the stream).
    ///
    /// If all data has been sent and acknowledged by the peer(the stream has closed), or the stream
    /// has been reset, this method will do nothing.
    ///
    /// Otherwise, a [`RESET_STREAM frame`] will be sent to the peer, and the stream will be reset,
    /// neither new data nor lost data will be sent.
    ///
    /// [`RESET_STREAM frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
    pub fn cancel(&mut self, err_code: u64) {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::Ready(s) => {
                    *sending_state = Sender::ResetSent(s.cancel(err_code));
                }
                Sender::Sending(s) => {
                    *sending_state = Sender::ResetSent(s.cancel(err_code));
                }
                Sender::DataSent(s) => {
                    *sending_state = Sender::ResetSent(s.cancel(err_code));
                }
                _ => (),
            }
        };
    }
}

impl<TX: Unpin> Unpin for Writer<TX> {}

impl<TX: Clone> AsyncWrite for Writer<TX> {
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
            Sender::DataSent(s) => s.poll_flush(cx),
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
            Sender::Ready(s) => s.poll_shutdown(cx),
            Sender::Sending(s) => s.poll_shutdown(cx),
            Sender::DataSent(s) => s.poll_shutdown(cx),
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

impl<TX> Drop for Writer<TX> {
    fn drop(&mut self) {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            debug_assert!(
                matches!(
                    sending_state,
                    Sender::DataRcvd | Sender::ResetSent(_) | Sender::ResetRcvd(_)
                ),
                "SendingStream must be shutdowned or cancelled before dropped!"
            );
        };
    }
}
