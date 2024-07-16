use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use qbase::frame::ConnectionCloseFrame;

/// When a connection enters the Closing state, only the
/// ConnectionCloseFrame needs to be retained.
#[derive(Debug)]
/// Represents the raw closing state of a connection.
struct RawClosingState {
    ccf: ConnectionCloseFrame,
    // When in the ClosingState, if the time to receive a packet
    // exceeds last_sent_time for too long, send CCF again.
    last_sent_time: Instant,
    // If the number of packets received from the other party exceeds
    // a certain number since the last CCF was sent, send CCF again.
    rcvd_packets: usize,
    // If the ClosingState is finished, notify the packet sending task to end.
    is_finished: bool,
    waker: Option<Waker>,
}

impl RawClosingState {
    fn new(ccf: ConnectionCloseFrame) -> Self {
        Self {
            ccf,
            last_sent_time: Instant::now(),
            rcvd_packets: 0,
            is_finished: false,
            waker: None,
        }
    }

    fn on_rcvd(&mut self) {
        if !self.is_finished {
            self.rcvd_packets += 1;
            if self.rcvd_packets >= 5 || self.last_sent_time.elapsed() >= Duration::from_millis(30)
            {
                if let Some(w) = self.waker.take() {
                    w.wake()
                }
            }
        }
    }

    fn poll_send_ccf(&mut self, cx: &mut Context<'_>) -> Poll<Option<ConnectionCloseFrame>> {
        if self.is_finished {
            Poll::Ready(None)
        } else if self.rcvd_packets >= 5
            || self.last_sent_time.elapsed() >= Duration::from_millis(30)
        {
            self.rcvd_packets = 0;
            self.last_sent_time = Instant::now();
            Poll::Ready(Some(self.ccf.clone()))
        } else {
            self.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    /// When timed out or receiving a ConnectionCloseFrame in this state,
    /// call this function to finish.
    fn finish(&mut self) {
        if !self.is_finished {
            self.is_finished = true;
            if let Some(w) = self.waker.take() {
                w.wake()
            }
        }
    }
}

/// ClosingState,
/// - needs to receive a packet as feedback to the ClosingState;
/// - it needs to constantly inquire whether to send, when receiving a certain
///   number of packets, or still receiving packets after a period of time;
/// - if CCF is received, it needs to finish.
#[derive(Debug, Clone)]
pub struct ArcClosingState(Arc<Mutex<RawClosingState>>);

/// Represents the state of a connection closing process.
///
/// The `ArcClosingState` struct provides methods for creating a new closing state, handling received frames,
/// sending connection close frames, and finishing the closing process.
impl ArcClosingState {
    /// Creates a new `ArcClosingState` with the specified connection close frame and timeout duration.
    ///
    /// # Arguments
    ///
    /// * `ccf` - The connection close frame to be used.
    /// * `timeout` - The duration after which the closing process will be finished.
    ///
    /// # Returns
    ///
    /// A new `ArcClosingState` instance.
    pub fn new(ccf: ConnectionCloseFrame, timeout: Duration) -> Self {
        let closing_state = ArcClosingState(Arc::new(Mutex::new(RawClosingState::new(ccf))));

        // Spawn a new Tokio task to finish the closing process after the specified timeout.
        tokio::spawn({
            let closing_state = closing_state.clone();
            async move {
                tokio::time::sleep(timeout).await;
                closing_state.finish();
            }
        });

        closing_state
    }

    /// Handles the received frame during the closing process.
    pub fn on_rcvd(&self) {
        self.0.lock().unwrap().on_rcvd();
    }

    /// Return a `SendCcf` struct that can be used to send a connection close frame.
    pub fn send_ccf(&self) -> SendCcf {
        SendCcf(self.clone())
    }

    /// Finishes the closing process by calling the `finish` method of the internal `RawClosingState`.
    pub fn finish(&self) {
        self.0.lock().unwrap().finish();
    }
}

pub struct SendCcf(ArcClosingState);

impl futures::Future for SendCcf {
    type Output = Option<ConnectionCloseFrame>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0 .0.lock().unwrap().poll_send_ccf(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        task::{Context, Poll},
        time::Duration,
    };

    use futures::Future;
    use qbase::{error::ErrorKind, frame::FrameType};
    use tokio::time::sleep;

    use super::*;

    fn default_ccf() -> ConnectionCloseFrame {
        ConnectionCloseFrame {
            error_kind: ErrorKind::FlowControl,
            frame_type: Some(FrameType::Stream(0b110)),
            reason: "wrong".into(),
        }
    }

    #[test]
    fn test_raw_closing_state_new() {
        let state = RawClosingState::new(default_ccf());
        assert_eq!(state.ccf, default_ccf());
        assert_eq!(state.rcvd_packets, 0);
        assert!(!state.is_finished);
        assert!(state.waker.is_none());
    }

    #[test]
    fn test_raw_closing_state_on_rcvd() {
        let mut state = RawClosingState::new(default_ccf());
        state.on_rcvd();
        assert_eq!(state.rcvd_packets, 1);
    }

    #[test]
    fn test_raw_closing_state_poll_send_ccf() {
        let mut state = RawClosingState::new(default_ccf());
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());

        // Test Poll::Pending
        assert_eq!(state.poll_send_ccf(&mut cx), Poll::Pending);

        // Test Poll::Ready(Some(ccf))
        state.rcvd_packets = 5;
        assert_eq!(
            state.poll_send_ccf(&mut cx),
            Poll::Ready(Some(default_ccf()))
        );
        assert_eq!(state.rcvd_packets, 0);

        // Test Poll::Ready(None)
        state.is_finished = true;
        assert_eq!(state.poll_send_ccf(&mut cx), Poll::Ready(None));
    }

    #[test]
    fn test_raw_closing_state_finish() {
        let mut state = RawClosingState::new(default_ccf());
        state.finish();
        assert!(state.is_finished);
    }

    #[tokio::test]
    async fn test_arc_closing_state_new() {
        let state = ArcClosingState::new(default_ccf(), Duration::from_millis(100));
        assert_eq!(state.0.lock().unwrap().ccf, default_ccf());
    }

    #[tokio::test]
    async fn test_arc_closing_state_on_rcvd() {
        let state = ArcClosingState::new(default_ccf(), Duration::from_millis(100));
        state.on_rcvd();
        assert_eq!(state.0.lock().unwrap().rcvd_packets, 1);
    }

    #[tokio::test]
    async fn test_arc_closing_state_send_ccf() {
        let state = ArcClosingState::new(default_ccf(), Duration::from_millis(100));
        let mut send_ccf = state.send_ccf();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());

        // Test Poll::Pending
        assert_eq!(Pin::new(&mut send_ccf).poll(&mut cx), Poll::Pending);

        // Test Poll::Ready(Some(ccf))
        state.0.lock().unwrap().rcvd_packets = 5;
        assert_eq!(
            Pin::new(&mut send_ccf).poll(&mut cx),
            Poll::Ready(Some(default_ccf()))
        );
        assert_eq!(state.0.lock().unwrap().rcvd_packets, 0);

        // Test Poll::Ready(None)
        state.0.lock().unwrap().is_finished = true;
        assert_eq!(Pin::new(&mut send_ccf).poll(&mut cx), Poll::Ready(None));
    }

    #[tokio::test]
    async fn test_arc_closing_state_finish() {
        let state = ArcClosingState::new(default_ccf(), Duration::from_millis(100));
        state.finish();
        assert!(state.0.lock().unwrap().is_finished);
    }

    #[tokio::test]
    async fn test_arc_closing_state_timeout() {
        let state = ArcClosingState::new(default_ccf(), Duration::from_millis(100));
        sleep(Duration::from_millis(150)).await;
        assert!(state.0.lock().unwrap().is_finished);
        let send_ccf = state.send_ccf().await;
        assert!(send_ccf.is_none());
    }

    #[tokio::test]
    async fn test_waker_on_rcvd() {
        let state = ArcClosingState::new(default_ccf(), Duration::from_millis(100));
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let mut send_ccf = state.send_ccf();
        assert_eq!(Pin::new(&mut send_ccf).poll(&mut cx), Poll::Pending);
        state.0.lock().unwrap().rcvd_packets = 5;
        state.on_rcvd();
        assert!(!state.0.lock().unwrap().is_finished);
        assert!(state.0.lock().unwrap().waker.is_none());
    }

    #[tokio::test]
    async fn test_waker_finish() {
        let state = ArcClosingState::new(default_ccf(), Duration::from_millis(100));
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let mut send_ccf = state.send_ccf();
        assert_eq!(Pin::new(&mut send_ccf).poll(&mut cx), Poll::Pending);
        state.finish();
        assert!(state.0.lock().unwrap().is_finished);
        assert!(state.0.lock().unwrap().waker.is_none());
    }
}
