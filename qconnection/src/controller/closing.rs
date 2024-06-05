use qbase::frame::ConnectionCloseFrame;
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

/// 当一个连接进入到Closing状态，只需保留ConnectionCloseFrame,
#[derive(Debug)]
struct RawClosingState {
    ccf: ConnectionCloseFrame,
    // 当在ClosingState下，收一个包的时间超过last_sent_time太久，就再发送一次CCF
    last_sent_time: Instant,
    // 如果距离上次发送CCF后，累计收到对方的包超过一定次数，就再发送一次CCF
    rcvd_packets: usize,
    // 如果Closing结束了，要告知发包任务结束
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
            if self.rcvd_packets >= 5 {
                if let Some(w) = self.waker.take() {
                    w.wake()
                }
            }

            if self.last_sent_time.elapsed() >= Duration::from_millis(30) {
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

    // 当超时了，或者在此状态下，收到了ConnectionCloseFrame，可调该函数结束
    fn finish(&mut self) {
        self.is_finished = true;
        if let Some(a) = self.waker.take() {
            a.wake()
        }
    }
}

/// ClosingState，一边要接收到一个数据包反馈给ClosingState；
/// 一边要不停的询问是否要发送，当收到一定数量的包，或者过了一段时间仍能接收到数据包；
/// 一边要是接收到CCF，要调用结束，因为要上一个发送任务要终止。
#[derive(Debug, Clone)]
pub struct ArcClosingState(Arc<Mutex<RawClosingState>>);

impl ArcClosingState {
    pub fn new(ccf: ConnectionCloseFrame) -> Self {
        ArcClosingState(Arc::new(Mutex::new(RawClosingState::new(ccf))))
    }

    pub fn on_rcvd(&self) {
        self.0.lock().unwrap().on_rcvd();
    }

    pub fn send_ccf(&self) -> SendCcf {
        SendCcf(self.clone())
    }

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
