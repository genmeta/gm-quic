use std::ops::{DerefMut, Range};

use bytes::BufMut;
use qbase::{
    error::Error as QuicError,
    frame::{io::WriteDataFrame, ResetStreamError, ShouldCarryLength, StreamFrame},
    sid::StreamId,
    util::DescribeData,
    varint::{VarInt, VARINT_MAX},
};

use super::sender::{ArcSender, DataSentSender, Sender, SendingSender};

/// An struct for protocol layer to manage the sending part of a stream.
#[derive(Debug, Clone)]
pub struct Outgoing<TX>(ArcSender<TX>);

impl<TX: Clone> Outgoing<TX> {
    /// Read the data that the application has written into the buffer.
    ///
    /// See [`DataStreams::try_read_data`] for more about this method.
    ///
    /// ## Returns:
    ///
    /// If no data is written to the buffer, return [`None`], or a tuple will be returned:
    /// * [`StreamFrame`]: Stream frame obtained by reading
    /// * [`usize`]:       The length of the stream data that was read
    /// * [`bool`]:        Whether the data is fresh(not retransmitted)
    /// * [`usize`]:       How much data was written to the buffer
    ///
    /// [`DataStreams::try_read_data`]: crate::streams::raw::DataStreams::try_read_data
    pub fn try_read(
        &self,
        sid: StreamId,
        mut buf: &mut [u8],
        tokens: usize,
        flow_limit: usize,
    ) -> Option<(StreamFrame, usize, bool, usize)> {
        let capacity = buf.len();
        let write = |(offset, is_fresh, data, is_eos): (u64, bool, (&[u8], &[u8]), bool)| {
            let mut frame = StreamFrame::new(sid, offset, data.len());

            frame.set_eos_flag(is_eos);
            match frame.should_carry_length(capacity) {
                ShouldCarryLength::NoProblem => {
                    buf.put_data_frame(&frame, &data);
                }
                ShouldCarryLength::PaddingFirst(n) => {
                    (&mut buf[n..]).put_data_frame(&frame, &data);
                }
                ShouldCarryLength::ShouldAfter(_not_carry_len, _carry_len) => {
                    frame.carry_length();
                    buf.put_data_frame(&frame, &data);
                }
            }
            (frame, data.len(), is_fresh, capacity - buf.remaining_mut())
        };

        let predicate = |offset| {
            StreamFrame::estimate_max_capacity(capacity, sid, offset).map(|c| tokens.min(c))
        };
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();

        match inner {
            Ok(sending_state) => match sending_state {
                Sender::Ready(s) => {
                    let result;
                    if s.is_finished() {
                        let mut s: DataSentSender<TX> = s.into();
                        result = s.pick_up(predicate, flow_limit).map(write);
                        *sending_state = Sender::DataSent(s);
                    } else {
                        let mut s: SendingSender<TX> = s.into();
                        result = s.pick_up(predicate, flow_limit).map(write);
                        *sending_state = Sender::Sending(s);
                    }
                    result
                }
                Sender::Sending(s) => s.pick_up(predicate, flow_limit).map(write),
                Sender::DataSent(s) => s.pick_up(predicate, flow_limit).map(write),
                _ => None,
            },
            Err(_) => None,
        }
    }
}

impl<TX> Outgoing<TX> {
    /// Create a new instance of [`Outgoing`]
    pub fn new(sender: ArcSender<TX>) -> Self {
        Self(sender)
    }

    /// Update the sending window to `max_data_size`
    ///
    /// Callded when the  [`MAX_STREAM_DATA frame`] belonging to the stream is received.
    ///
    /// [`MAX_STREAM_DATA frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-max_stream_data-frames
    pub fn update_window(&self, max_stream_data: u64) {
        assert!(max_stream_data <= VARINT_MAX);
        let mut sender = self.0.sender();
        match sender.deref_mut() {
            Ok(Sender::Ready(s)) => s.update_window(max_stream_data),
            Ok(Sender::Sending(s)) => s.update_window(max_stream_data),
            _ => {}
        }
    }

    /// Called when the data sent to peer is acknowlwged.
    ///
    /// * `range` is the range of stream data that has been acknowledged.
    ///
    /// * `is_fin` indicates whether the acknowledged stream frame contains the `FIN` flag.
    ///
    /// Return `true` if the stream is completely acknowledged, all data has been sent and received.
    ///
    /// [`SendBuf`]: crate::send::SendBuf
    pub fn on_data_acked(&self, range: &Range<u64>, is_fin: bool) -> bool {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::Ready(_) => {
                    unreachable!("never send data before recv data");
                }
                Sender::Sending(s) => {
                    s.on_data_acked(range);
                }
                Sender::DataSent(s) => {
                    s.on_data_acked(range, is_fin);
                    if s.is_all_rcvd() {
                        s.wake_all();
                        *sending_state = Sender::DataRcvd;
                        return true;
                    }
                }
                // ignore recv
                _ => {}
            }
        };
        false
    }

    /// Called when the data sent to peer may lost.
    ///
    /// * `range` is the range of stream data that may lost.
    pub fn may_loss_data(&self, range: &Range<u64>) {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::Ready(_) => {
                    unreachable!("never send data before recv data");
                }
                Sender::Sending(s) => {
                    s.may_loss_data(range);
                }
                Sender::DataSent(s) => {
                    s.may_loss_data(range);
                }
                // ignore loss
                _ => (),
            }
        };
    }

    /// Called when the [`STOP_SENDING frame`] sent by the peer is received.
    ///
    /// If the stream has not been closed, the stream will be reset and then a [`RESET_STREAM frame`] will
    /// be sent to the peer to reset the peer. in this case, the method will return `true`.
    ///
    /// If the stream has closed, `false` will be returned, and the method will do nothing.
    ///
    /// [`STOP_SENDING frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames
    /// [`STREAM_RESET frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
    pub fn on_stopped(&self, error_code: u64) -> bool {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state {
                Sender::Ready(_) => {
                    unreachable!("never send data before recv data");
                }
                Sender::Sending(s) => {
                    let final_size = s.stop();
                    *sending_state = Sender::ResetSent(ResetStreamError::new(
                        VarInt::from_u64(error_code).expect("app error code must not exceed 2^62"),
                        VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
                    ));
                    true
                }
                Sender::DataSent(s) => {
                    let final_size = s.stop();
                    *sending_state = Sender::ResetSent(ResetStreamError::new(
                        VarInt::from_u64(error_code).expect("app error code must not exceed 2^62"),
                        VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
                    ));
                    true
                }
                _ => false,
            },
            Err(_) => false,
        }
    }

    /// Called When the [`RESET_STREAM frame`] previously sent to the peer is acknowledged
    ///
    /// [`RESET_STREAM frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
    pub fn on_reset_acked(&self) {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::ResetSent(r) | Sender::ResetRcvd(r) => {
                    *sending_state = Sender::ResetRcvd(*r)
                }
                _ => {
                    unreachable!(
                    "If no RESET_STREAM has been sent, how can there be a received acknowledgment?"
                    );
                }
            }
        }
    }

    /// When a connection-level error occurs, all data streams must be notified.
    /// Their reading and writing should be terminated, accompanied the error of the connection.
    pub fn on_conn_error(&self, err: &QuicError) {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state {
                Sender::Ready(s) => s.wake_all(),
                Sender::Sending(s) => s.wake_all(),
                Sender::DataSent(s) => s.wake_all(),
                _ => return,
            },
            Err(_) => return,
        };
        *inner = Err(err.clone());
    }
}
