use std::ops::DerefMut;

use bytes::Bytes;
use qbase::{
    error::Error as QuicError,
    frame::{MaxStreamDataFrame, ResetStreamFrame, SendFrame, StopSendingFrame, StreamFrame},
};

use super::recver::{ArcRecver, Recver};

/// An struct for protocol layer to manage the receiving part of a stream.
#[derive(Debug, Clone)]
pub struct Incoming<TX>(pub(crate) ArcRecver<TX>);

impl<TX> Incoming<TX>
where
    TX: SendFrame<StopSendingFrame> + SendFrame<MaxStreamDataFrame> + Clone + Send + 'static,
{
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
        let mut fresh_data = 0;
        if let Ok(receiving_state) = inner {
            match receiving_state {
                Recver::Recv(r) => {
                    if stream_frame.is_fin() {
                        let final_size = stream_frame.offset() + stream_frame.len() as u64;
                        let mut size_known = r.determin_size(final_size);
                        fresh_data = size_known.recv(stream_frame, body)?;
                        if size_known.is_all_rcvd() {
                            *receiving_state = Recver::DataRcvd(size_known.into());
                        } else {
                            *receiving_state = Recver::SizeKnown(size_known);
                        }
                    } else {
                        fresh_data = r.recv(stream_frame, body)?;
                    }
                }
                Recver::SizeKnown(r) => {
                    fresh_data = r.recv(stream_frame, body)?;
                    if r.is_all_rcvd() {
                        *receiving_state = Recver::DataRcvd(r.into());
                    }
                }
                _ => {
                    log::debug!("ignored stream frame {:?}", stream_frame);
                }
            }
        }
        Ok(fresh_data)
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
}

impl<TX> Incoming<TX> {
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
                Recver::Recv(r) => r.wake_reader(),
                Recver::SizeKnown(r) => r.wake_reader(),
                _ => return,
            },
            Err(_) => return,
        };
        *inner = Err(err.clone());
    }
}
