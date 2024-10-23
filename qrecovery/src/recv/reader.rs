use std::{
    io,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

use qbase::{sid::StreamId, varint::VARINT_MAX};
use tokio::io::{AsyncRead, ReadBuf};

use super::recver::{ArcRecver, Recver};

/// The reader part of a QUIC stream.
///
/// A QUIC stream is *reliable*, *ordered*, and *flow-controlled*.
///
/// This struct implements the [`AsyncRead`] trait, allowing you to read an ordered byte stream from
/// the peer, like [`TcpStream`].
///
/// Try to read from the [`Reader`] into a non-empty buffer, the [`Reader`] will block until some data
/// is available, or the stream is closed, or the stream is reset by peer.
///
/// # Note
///
/// The stream must be closed before [`Reader`] dropped.
///
/// The [`read`] returning `Ok(0)` indicates that all data from peer has been read and the stream has
/// `closed`, it is okay to drop the [`Reader`] after that.
///
/// Alternatively, if the [`read`] result an error, its indicates that the stream has been `reset`, or
/// closed duo to other reasons. It's also okay to drop the [`Reader`] after that.
///
/// You can call [`stop`] to tell the peer to stop sending data with the given error code, the [`Reader`]
/// will be consumed, and the error code will be sent to the peer.
///
/// # Example
///
/// The [`Reader`] is created by the `open_bi_stream`, `accept_bi_stream`, or `accept_uni_stream` methods
/// of `QuicConnection` (in the `quic` crate).
///
/// The following example demonstrates how to read and write data on a QUIC stream:
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
/// [`TcpStream`]: tokio::net::TcpStream
/// [`read`]: tokio::io::AsyncReadExt::read
/// [`stop`]: Reader::stop
/// [`RESET_STREAM frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
#[derive(Debug)]
pub struct Reader(pub(crate) ArcRecver);

impl Reader {
    /// Tell peer to stop sending data with the given error code.
    ///
    /// If all data has been received(the stream has closed), or the stream has been reset, this method will do
    /// nothing.
    ///
    /// Otherwise, a [`STOP_SENDING frame`] will be sent to the peer, and then the stream will be reset by peer.
    ///
    /// [`STOP_SENDING frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames
    pub fn stop(&mut self, error_code: u64) {
        debug_assert!(error_code <= VARINT_MAX);
        let mut recver = self.0.recver();
        let inner = recver.deref_mut();
        if let Ok(receiving_state) = inner {
            match receiving_state {
                Recver::Recv(r) => {
                    r.stop(error_code);
                }
                Recver::SizeKnown(r) => {
                    r.stop(error_code);
                }
                _ => (),
            }
        }
    }

    /// Returns the stream ID of the stream.
    pub fn stream_id(&self) -> StreamId {
        self.0.sid()
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut recver = self.0.recver();
        let receiving_state = recver.as_mut().map_err(|e| e.clone())?;
        // 能相当清楚地看到应用层读取数据驱动的接收状态演变
        match receiving_state {
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
            Recver::ResetRcvd(reset) => {
                let reset = *reset;
                *receiving_state = Recver::ResetRead(reset);
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, reset)))
            }
            Recver::ResetRead(reset) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, *reset)))
            }
        }
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        let mut recver = self.0.recver();
        let inner = recver.deref_mut();
        if let Ok(receiving_state) = inner {
            match receiving_state {
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
            }
        }
    }
}

#[cfg(test)]
mod tests {}
