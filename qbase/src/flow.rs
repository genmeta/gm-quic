use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};

use crate::{
    error::{Error as QuicError, ErrorKind as QuicErrorKind},
    frame::{DataBlockedFrame, FrameType, MaxDataFrame, ReceiveFrame, SendFrame},
    net::FlowWakers,
    varint::VarInt,
};

/// Connection-level global Stream Flow Control in the sending direction,
/// regulated by the peer's `initial_max_data` transport parameter
/// and updated by the [`MaxDataFrame`] sent by the peer.
///
/// Private controler in [`ArcSendControler`].
#[derive(Debug, Default)]
struct SendControler<TX> {
    sent_data: u64,
    max_data: u64,
    blocking: bool,
    broker: TX,
    wakers: FlowWakers,
}

impl<TX> SendControler<TX> {
    fn new(initial_max_data: u64, broker: TX, flow_wakers: FlowWakers) -> Self {
        Self {
            sent_data: 0,
            max_data: initial_max_data,
            blocking: false,
            broker,
            wakers: flow_wakers,
        }
    }

    fn increase_limit(&mut self, max_data: u64) {
        if max_data > self.max_data {
            self.max_data = max_data;
            self.blocking = false;
            self.wakers.wake_all();
        }
    }
}

/// Shared connection-level Stream Flow Control in the sending direction,
/// regulated by the peer's `initial_max_data` transport parameter
/// and updated by the [`MaxDataFrame`] received from the peer.
///
/// Only the new data sent in [`StreamFrame`](`crate::frame::StreamFrame`) counts toward this limit.
/// Retransmitted stream data does not count towards this limit.
///
/// When flow control is 0,
/// retransmitted stream data can still be sent,
/// but new data cannot be sent.
/// When the stream has no data to retransmit,
/// meaning all old data has been successfully acknowledged,
/// it is necessary to wait for the receiver's [`MaxDataFrame`]`
/// to increase the connection-level flow control limit.
///
/// To avoid having to pause sending tasks while waiting for the [`MaxDataFrame`],
/// the receiver should promptly send the [`MaxDataFrame`]
/// to increase the flow control limit,
/// ensuring that the sender always has enough space to send smoothly.
/// An extreme yet simple strategy is to set the flow control limit to infinity from the start,
/// causing the connection-level flow control to never reach its limit,
/// effectively rendering it useless.
#[derive(Clone, Debug)]
pub struct ArcSendControler<TX>(Arc<Mutex<Result<SendControler<TX>, QuicError>>>);

impl<TX> ArcSendControler<TX> {
    /// Creates a new [`ArcSendControler`] with `initial_max_data`.
    ///
    /// `initial_max_data` should be known to each other after the handshake is
    /// completed. If sending data in 0-RTT space, `initial_max_data` should be
    /// the value from the previous connection.
    ///
    /// `initial_max_data` is allowed to be 0, which is reasonable when creating a
    /// connection without knowing the peer's `iniitial_max_data` setting.
    pub fn new(initial_max_data: u64, broker: TX, flow_wakers: FlowWakers) -> Self {
        Self(Arc::new(Mutex::new(Ok(SendControler::new(
            initial_max_data,
            broker,
            flow_wakers,
        )))))
    }

    fn increase_limit(&self, max_data: u64) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(inner) = guard.deref_mut() {
            inner.increase_limit(max_data);
        }
    }

    // Get some flow control credit to send fresh flow data.
    /// The returned value may be smaller than the parameter's intended value.
    /// If some QUIC error occured, it would return the error directly.
    ///
    /// # Note
    ///
    /// After obtaining the flow control,
    /// the traffic credit is considered to be consumed immediately.
    /// The unused flow control quota for this send will be returned to the sending controller.
    /// This design avoids the sending task’s exclusive access to the sending controller.
    pub fn credit(&self, quota: usize) -> Result<Credit<'_, TX>, QuicError>
    where
        TX: SendFrame<DataBlockedFrame>,
    {
        match self.0.lock().unwrap().as_mut() {
            Ok(inner) => {
                let avaliable = (inner.max_data - inner.sent_data).min(quota as u64);
                inner.sent_data += avaliable;
                if inner.sent_data == inner.max_data && !inner.blocking {
                    inner.blocking = true;
                    inner.broker.send_frame([DataBlockedFrame::new(
                        VarInt::from_u64(inner.max_data).expect(
                            "max_data of flow controller is very very hard to exceed 2^62 - 1",
                        ),
                    )]);
                }
                Ok(Credit {
                    available: avaliable as usize,
                    controller: self,
                })
            }
            Err(e) => Err(e.clone()),
        }
    }

    /// Connection-level Stream Flow Control can only be terminated
    /// if the connection encounters an error
    pub fn on_error(&self, error: &QuicError) {
        let mut guard = self.0.lock().unwrap();
        if guard.deref().is_err() {
            return;
        }
        *guard = Err(error.clone());
    }
}

/// [`ArcSendControler`] need to receive [`MaxDataFrame`] from peer
/// to increase flow control limit continuely.
impl<TX> ReceiveFrame<MaxDataFrame> for ArcSendControler<TX> {
    type Output = ();

    fn recv_frame(&self, frame: &MaxDataFrame) -> Result<Self::Output, QuicError> {
        self.increase_limit(frame.max_data());
        Ok(())
    }
}

/// Exclusive access to the flow control limit.
///
/// As mentioned in the [`ArcSendControler::credit`] method,
/// the flow controller in the period between obtaining flow control
/// and finally updating(or maybe not) the flow control should be exclusive.
pub struct Credit<'a, TX> {
    available: usize,
    controller: &'a ArcSendControler<TX>,
}

impl<TX> Credit<'_, TX> {
    /// Return the available amount of new stream data that can be sent.
    pub fn available(&self) -> usize {
        self.available
    }
}

impl<TX> Credit<'_, TX>
where
    TX: SendFrame<DataBlockedFrame>,
{
    /// Updates the amount of new data sent.
    pub fn post_sent(&mut self, amount: usize) {
        self.available -= amount;
    }
}

impl<TX> Drop for Credit<'_, TX> {
    fn drop(&mut self) {
        if let Ok(inner) = self.controller.0.lock().unwrap().as_mut() {
            inner.sent_data -= self.available as u64;
            if self.available > 0 {
                inner.wakers.wake_all();
            }
        }
    }
}

/// Receiver's flow controller for managing the flow limit of incoming stream data.
#[derive(Debug, Default)]
struct RecvController<TX> {
    rcvd_data: u64,
    max_data: u64,
    step: u64,
    is_closed: bool,
    broker: TX,
}

impl<TX> RecvController<TX> {
    /// Creates a new [`RecvController`] with the specified `initial_max_data`.
    fn new(initial_max_data: u64, broker: TX) -> Self {
        Self {
            rcvd_data: 0,
            max_data: initial_max_data,
            step: initial_max_data / 2,
            is_closed: false,
            broker,
        }
    }

    /// Terminate the receiver's flow control.
    fn terminate(&mut self) {
        self.is_closed = true;
    }
}

impl<TX> RecvController<TX>
where
    TX: SendFrame<MaxDataFrame>,
{
    /// Handles the event when new data is received.
    ///
    /// The data must be new, old retransmitted data does not count. Whether the data is
    /// new or not will be determined by each stream after delivering the data packet to them.
    /// The amount of new data will be passed as the `amount` parameter.
    fn on_new_rcvd(&mut self, frame_type: FrameType, amount: usize) -> Result<usize, QuicError> {
        debug_assert!(!self.is_closed);

        self.rcvd_data += amount as u64;
        if self.rcvd_data <= self.max_data {
            if self.rcvd_data + self.step >= self.max_data {
                self.max_data += self.step;
                self.broker
                    .send_frame([MaxDataFrame::new(VarInt::from_u64(self.max_data).expect(
                        "max_data of flow controller is very very hard to exceed 2^62 - 1",
                    ))])
            }
            Ok(amount)
        } else {
            // Err(Overflow((rcvd_data - max_data) as usize))
            Err(QuicError::new(
                QuicErrorKind::FlowControl,
                frame_type,
                format!("flow control overflow: {}", self.rcvd_data - self.max_data),
            ))
        }
    }
}

/// Shared receiver's flow controller for managing the incoming stream data flow.
///
/// Flow control on the receiving end,
/// primarily used to regulate the data flow sent by the sender.
/// Since the receive buffer is limited,
/// if the application layer cannot read the data in time,
/// the receive buffer will not expand, and the sender must be suspended.
///
/// The sender must never send new stream data exceeding
/// the flow control limit of the receiver advertised,
/// otherwise it will be considered a [`FlowControl`](`crate::error::ErrorKind::FlowControl`) error.
///
/// Additionally, the flow control on the receiving end also needs to
/// promptly send a [`MaxDataFrame`] to the sender after the application layer reads the data,
/// to expand the receive window since more receive buffer space is freed up,
/// and to inform the sender that more data can be sent.
#[derive(Debug, Default, Clone)]
pub struct ArcRecvController<TX>(Arc<Mutex<RecvController<TX>>>);

impl<TX> ArcRecvController<TX> {
    /// Creates a new [`ArcRecvController`] with local `initial_max_data` transport parameter.
    pub fn new(initial_max_data: u64, broker: TX) -> Self {
        Self(Arc::new(Mutex::new(RecvController::new(
            initial_max_data,
            broker,
        ))))
    }

    /// Terminate the receiver's flow control if QUIC connection error occurs.
    pub fn terminate(&self) {
        self.0.lock().unwrap().terminate();
    }
}

impl<TX> ArcRecvController<TX>
where
    TX: SendFrame<MaxDataFrame>,
{
    /// Updates the total received data size and checks if the flow control limit is exceeded
    /// when new stream data is received.
    ///
    /// As mentioned in [`ArcSendControler`], if the flow control limit is exceeded,
    /// a [`QuicError`] error will be returned.
    pub fn on_new_rcvd(&self, frame_type: FrameType, amount: usize) -> Result<usize, QuicError> {
        self.0.lock().unwrap().on_new_rcvd(frame_type, amount)
    }
}

/// [`ArcRecvController`] need to receive [`DataBlockedFrame`] from peer.
///
/// However, the receiver may also not be able to immediately expand the receive window
/// and must wait for the application layer to read the data to free up more space
/// in the receive buffer.
impl<TX> ReceiveFrame<DataBlockedFrame> for ArcRecvController<TX> {
    type Output = ();

    fn recv_frame(&self, _frame: &DataBlockedFrame) -> Result<Self::Output, QuicError> {
        // Do nothing
        Ok(())
    }
}

/// Connection-level flow controller, including an [`ArcSendControler`] as the sending side
/// and an [`ArcRecvController`] as the receiving side.
#[derive(Debug, Clone)]
pub struct FlowController<TX> {
    pub sender: ArcSendControler<TX>,
    pub recver: ArcRecvController<TX>,
}

impl<TX: Clone> FlowController<TX> {
    /// Creates a new `FlowController` with the specified initial send and receive window sizes.
    ///
    /// Unfortunately, at the beginning, the peer's `initial_max_data` is unknown.
    /// Therefore, peer's `initial_max_data` can be set to 0 initially,
    /// and then updated later after obtaining the peer's `initial_max_data` setting.
    pub fn new(
        peer_initial_max_data: u64,
        local_initial_max_data: u64,
        broker: TX,
        flow_wakers: FlowWakers,
    ) -> Self {
        Self {
            sender: ArcSendControler::new(peer_initial_max_data, broker.clone(), flow_wakers),
            recver: ArcRecvController::new(local_initial_max_data, broker),
        }
    }

    /// Updates the initial send window size,
    /// which should be the peer's `initial_max_data` transport parameter.
    /// So once the peer's [`Parameters`](`crate::param::Parameters`) are obtained,
    /// this method should be called immediately.
    pub fn reset_send_window(&self, snd_wnd: u64) {
        self.sender.increase_limit(snd_wnd);
    }

    /// Get some flow control credit to send fresh flow data.
    /// The returned value may be smaller than the parameter's intended value.
    /// If some QUIC error occured, it would return the error directly.
    pub fn send_limit(&self, quota: usize) -> Result<Credit<'_, TX>, QuicError>
    where
        TX: SendFrame<DataBlockedFrame>,
    {
        self.sender.credit(quota)
    }

    /// Handles the error event of the QUIC connection.
    ///
    /// It will makes
    /// the connection-level stream flow controller in the sending direction become unavailable,
    /// and the connection-level stream flow controller in the receiving direction terminate.
    pub fn on_conn_error(&self, error: &QuicError) {
        self.sender.on_error(error);
        self.recver.terminate();
    }
}

impl<TX> FlowController<TX>
where
    TX: SendFrame<MaxDataFrame>,
{
    /// Updates the total received data size and checks if the flow control limit is exceeded.
    /// By the way, it will also send a [`MaxDataFrame`] to the sender
    /// to expand the receive window if necessary.
    pub fn on_new_rcvd(&self, frame_type: FrameType, amount: usize) -> Result<usize, QuicError> {
        self.recver.on_new_rcvd(frame_type, amount)
    }
}

#[cfg(test)]
mod tests {
    use deref_derive::{Deref, DerefMut};

    use super::*;

    #[derive(Clone, Debug, Default, Deref, DerefMut)]
    struct SendControllerBroker(Arc<Mutex<Vec<DataBlockedFrame>>>);

    impl SendFrame<DataBlockedFrame> for SendControllerBroker {
        fn send_frame<I: IntoIterator<Item = DataBlockedFrame>>(&self, iter: I) {
            self.0.lock().unwrap().extend(iter);
        }
    }

    #[test]
    fn test_send_controler() {
        let broker = SendControllerBroker::default();
        let controler = ArcSendControler::new(100, broker.clone(), Default::default());
        let mut credit = controler.credit(200).unwrap();
        assert_eq!(credit.available(), 100);
        credit.post_sent(50);
        assert_eq!(credit.available(), 50);
        credit.post_sent(50);
        assert_eq!(credit.available(), 0);
        drop(credit);

        // broker should have a DataBlockedFrame
        assert_eq!(broker.lock().unwrap().len(), 1);
        assert_eq!(broker.lock().unwrap()[0].limit(), 100);

        let credit = controler.credit(1).unwrap();
        assert_eq!(credit.available(), 0);
        drop(credit);

        controler.increase_limit(200);

        let mut credit = controler.credit(200).unwrap();
        assert_eq!(credit.available(), 100);
        credit.post_sent(50);
        assert_eq!(credit.available(), 50);
        credit.post_sent(50);
        assert_eq!(credit.available(), 0);
        drop(credit);

        // broker should have a DataBlockedFrame
        assert_eq!(broker.lock().unwrap().len(), 2);
        assert_eq!(broker.lock().unwrap()[1].limit(), 200);
    }

    #[derive(Clone, Debug, Default, Deref, DerefMut)]
    struct RecvControllerBroker(Arc<Mutex<Vec<MaxDataFrame>>>);

    impl SendFrame<MaxDataFrame> for RecvControllerBroker {
        fn send_frame<I: IntoIterator<Item = MaxDataFrame>>(&self, iter: I) {
            self.0.lock().unwrap().extend(iter);
        }
    }

    #[test]
    fn test_recv_controller() {
        let broker = RecvControllerBroker::default();
        let controler = ArcRecvController::new(100, broker.clone());
        let amount = controler.on_new_rcvd(FrameType::Stream(0), 20).unwrap();
        assert_eq!(amount, 20);
        assert_eq!(broker.lock().unwrap().len(), 0);

        let amount = controler.on_new_rcvd(FrameType::Stream(3), 30).unwrap();
        assert_eq!(amount, 30);
        // broker should have a MaxDataFrame
        assert_eq!(broker.lock().unwrap().len(), 1);
        assert_eq!(broker.lock().unwrap()[0].max_data(), 150);

        // test overflow
        let result = controler.on_new_rcvd(FrameType::ResetStream, 101);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), QuicErrorKind::FlowControl);
    }
}
