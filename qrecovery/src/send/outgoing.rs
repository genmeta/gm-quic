use std::ops::{DerefMut, Range};

use bytes::BufMut;
use qbase::{
    error::Error as QuicError,
    frame::{ResetStreamError, StreamFrame},
    net::SendLimiter,
    packet::MarshalDataFrame,
    sid::StreamId,
    util::DescribeData,
    varint::{VARINT_MAX, VarInt},
};
use qlog::quic::transport::{GranularStreamStates, StreamSide, StreamStateUpdated};

use super::sender::{ArcSender, Sender, SendingSender};

/// An struct for protocol layer to manage the sending part of a stream.
#[derive(Debug, Clone)]
pub struct Outgoing<TX>(ArcSender<TX>);

impl<TX: Clone> Outgoing<TX> {
    /// Try to load data that the application wants to sent to the packet.
    ///
    /// See [`DataStreams::try_load_data_into`] for more about this method.
    ///
    /// Return the size of data loaded, and whether the data is fresh.
    ///
    /// [`DataStreams::try_load_data_into`]: crate::streams::raw::DataStreams::try_load_data_into
    // consume the token internally, return the number of fresh data have been written to the buffer.
    // return None indicates that the stream write no data to the buffer.
    pub fn try_load_data_into<P>(
        &self,
        packet: &mut P,
        sid: StreamId,
        flow_limit: usize,
        tokens: usize,
    ) -> Result<(usize, bool), SendLimiter>
    where
        P: BufMut + for<'a> MarshalDataFrame<StreamFrame, (&'a [u8], &'a [u8])>,
    {
        let origin_len = packet.remaining_mut();
        let mut write = |(offset, is_fresh, data, is_eos): (u64, bool, (&[u8], &[u8]), bool)| {
            let mut frame = StreamFrame::new(sid, offset, data.len());

            frame.set_eos_flag(is_eos);
            let strategy = frame.encoding_strategy(origin_len);
            frame.set_len_flag(strategy.carry_length());
            packet.put_bytes(0, strategy.padding());
            packet.dump_frame_with_data(frame, data);

            (data.len(), is_fresh)
        };

        let predicate = |offset| {
            StreamFrame::estimate_max_capacity(origin_len, sid, offset)
                .map(|capacity| tokens.min(capacity))
        };
        let mut sender = self.0.sender();
        let sending_state = sender.as_mut().or(Err(SendLimiter::empty()))?; // other(connection closed)

        match sending_state {
            Sender::Ready(s) => {
                let mut s: SendingSender<TX> = s.upgrade();
                let (result, finished) = s
                    .pick_up(predicate, flow_limit)
                    .map(|payload @ (.., with_eos)| (Ok(write(payload)), with_eos))
                    .map_err(|l| (Err(l), false))
                    .unwrap_or_else(|x| x);
                if finished {
                    *sending_state = Sender::DataSent(s.upgrade());
                } else {
                    *sending_state = Sender::Sending(s);
                }
                result
            }
            Sender::Sending(s) => {
                let (result, finished) = s
                    .pick_up(predicate, flow_limit)
                    .map(|payload @ (.., with_eos)| (Ok(write(payload)), with_eos))
                    .map_err(|l| (Err(l), false))
                    .unwrap_or_else(|x| x);
                if finished {
                    *sending_state = Sender::DataSent(s.upgrade());
                }
                result
            }
            Sender::DataSent(s) => s.pick_up(predicate, flow_limit).map(write),
            _ => Err(SendLimiter::NO_UNLIMITED_DATA),
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
    pub fn on_data_acked(&self, frame: &StreamFrame) -> bool {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::Ready(_) => {
                    unreachable!("never send data before recv data");
                }
                Sender::Sending(s) => {
                    s.on_data_acked(&frame.range());
                }
                Sender::DataSent(s) => {
                    s.on_data_acked(&frame.range(), frame.is_fin());
                    if s.is_all_rcvd() {
                        qlog::event!(StreamStateUpdated {
                            stream_id: frame.stream_id(),
                            stream_type: frame.stream_id().dir(),
                            old: GranularStreamStates::DataSent,
                            new: GranularStreamStates::DataReceived,
                            stream_side: StreamSide::Sending
                        });
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
    /// be sent to the peer to reset the peer with the `final_size`.
    /// In this case, the method will return the `final_size`.
    ///
    /// If the stream has closed, `None` will be returned, and the method will do nothing.
    ///
    /// [`STOP_SENDING frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames
    /// [`STREAM_RESET frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
    pub fn be_stopped(&self, error_code: u64) -> Option<u64> {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state {
                Sender::Ready(_) => {
                    unreachable!("never send data before recv data");
                }
                Sender::Sending(s) => {
                    let final_size = s.be_stopped();
                    let reset = ResetStreamError::new(
                        VarInt::from_u64(error_code).expect("app error code must not exceed 2^62"),
                        VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
                    );
                    *sending_state = Sender::ResetSent(reset);
                    Some(final_size)
                }
                Sender::DataSent(s) => {
                    let final_size = s.be_stopped();
                    let reset = ResetStreamError::new(
                        VarInt::from_u64(error_code).expect("app error code must not exceed 2^62"),
                        VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
                    );
                    *sending_state = Sender::ResetSent(reset);
                    Some(final_size)
                }
                _ => None,
            },
            Err(_) => None,
        }
    }

    /// Called When the [`RESET_STREAM frame`] previously sent to the peer is acknowledged
    ///
    /// [`RESET_STREAM frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
    pub fn on_reset_acked(&self, sid: StreamId) {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::ResetSent(r) => {
                    qlog::event!(StreamStateUpdated {
                        stream_id: sid,
                        stream_type: sid.dir(),
                        old: GranularStreamStates::ResetSent,
                        new: GranularStreamStates::ResetReceived,
                        stream_side: StreamSide::Sending
                    });
                    *sending_state = Sender::ResetRcvd(*r);
                }
                Sender::ResetRcvd(..) => {}
                _ => unreachable!(
                    "If no RESET_STREAM has been sent, how can there be a received acknowledgment?"
                ),
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
