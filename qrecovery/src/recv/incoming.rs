use std::{
    future::Future,
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

/// An struct for protocol layer to manage the receiving part of a stream.
#[derive(Debug, Clone)]
pub struct Incoming(pub(crate) ArcRecver);

impl Incoming {
    /// Receive a stream frame from peer.
    ///
    /// The stream frame will be handed over to the receive state machine.
    ///
    /// The data in a stream frame is just a fragment of the data on the stream. The data transmitted
    /// by different stream frames may not continuous. The data will be assembled by [`RecvBuf`] into
    /// continuous data for the application layer to read through [`Reader`].
    ///
    /// [`RecvBuf`]: crate::recv::RecvBuf
    /// [`Reader`]: crate::recv::Reader
    pub fn recv_data(&self, stream_frame: &StreamFrame, body: Bytes) -> Result<usize, QuicError> {
        let mut recver = self.0.recver();
        let inner = recver.deref_mut();
        let mut new_data_size = 0;
        if let Ok(receiving_state) = inner {
            match receiving_state {
                Recver::Recv(r) => {
                    if stream_frame.is_fin() {
                        let final_size = stream_frame.offset() + stream_frame.len() as u64;
                        let mut size_known = r.determin_size(final_size);
                        new_data_size = size_known.recv(stream_frame, body)?;
                        if size_known.is_all_rcvd() {
                            *receiving_state = Recver::DataRcvd(size_known.into());
                        } else {
                            *receiving_state = Recver::SizeKnown(size_known);
                        }
                    } else {
                        new_data_size = r.recv(stream_frame, body)?;
                    }
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

    /// Receive a stream reset frame from peer.
    ///
    /// If all data sent by the peer has not been received, receiving a stream reset frame will cause
    /// any read calls to return an error, received data will be discarded.
    pub fn recv_reset(&self, reset_frame: &ResetStreamFrame) -> Result<(), QuicError> {
        // TODO: ResetStream中还有错误信息，比如http3的错误码，看是否能用到
        let mut recver = self.0.recver();
        let inner = recver.deref_mut();
        if let Ok(receiving_state) = inner {
            match receiving_state {
                Recver::Recv(r) => {
                    let _final_size = r.recv_reset(reset_frame)?;
                    *receiving_state = Recver::ResetRcvd(reset_frame.into());
                }
                Recver::SizeKnown(r) => {
                    let _final_size = r.recv_reset(reset_frame)?;
                    *receiving_state = Recver::ResetRcvd(reset_frame.into());
                }
                _ => {
                    log::error!("there is sth wrong, ignored recv_reset");
                    unreachable!();
                }
            }
        }
        Ok(())
    }

    /// Called when a connecion error occured
    ///
    /// After the connection error occured, trying to read the data from [`Reader`] will result an
    /// Error.
    ///
    /// [`Reader`]: crate::recv::Reader
    pub fn on_conn_error(&self, err: &QuicError) {
        let mut recver = self.0.recver();
        let inner = recver.deref_mut();
        match inner {
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => r.wake_all(),
                Recver::SizeKnown(r) => r.wake_all(),
                _ => return,
            },
            Err(_) => return,
        };
        *inner = Err(err.clone());
    }

    /// Wait for the application layer to want to reset the stream.
    ///
    /// If the stream is closed, this future will complete too.
    ///
    /// See [`IsStopped`]'s doc for more details.
    pub fn is_stopped_by_app(&self) -> IsStopped {
        IsStopped(&self.0)
    }

    /// Waiting for the need to update the peer's sending window.
    ///
    /// If the stream is closed, this future will complete too.
    ///
    /// See [`UpdateWindow`]'s doc for more details.
    pub fn need_update_window(&self) -> UpdateWindow {
        UpdateWindow(&self.0)
    }
}

/// A future that returns whether the receiving buffer(sending window for `Sender`, flow control for
/// stream) needs to be grown.
///
/// This is used to notify the streams controller to update the flow control limit in time, and send
/// a [`MAX_STREAM_DATA frame`] to the peer.
///
/// Created by [`Incoming::need_update_window`].
///
/// Return [`None`] if its not necessary to update the window any more.
///
/// Reutrn [`Some`] with the new window size if the window needs to be updated.
///
/// [`MAX_STREAM_DATA frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-max_stream_data-frame
pub struct UpdateWindow<'r>(&'r ArcRecver);

impl Future for UpdateWindow<'_> {
    type Output = Option<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut recver = self.0.recver();
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

/// A future that returns whether the application layer wants the peer to stop sending data.
///
/// This is used to notify the protocol layer to send a [`STOP_SENDING frame`] after the application
/// layer calls [`stop`].
///
/// Created by [`Incoming::is_stopped_by_app`].
///
/// This future complete when the application layer calls [`stop`] on the stream, or the stream is
/// closed duo to other reasons.
///
/// If the stream is stopped by the application layer, return the application layer's error code.
///
/// If the application layer does not call [`stop`]  until the stream is closed, this method returns
/// [`None`].
///
/// [`stop`]: crate::recv::Reader::stop
/// [`STOP_SENDING frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames
pub struct IsStopped<'r>(&'r ArcRecver);

impl Future for IsStopped<'_> {
    type Output = Option<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut recver = self.0.recver();
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
