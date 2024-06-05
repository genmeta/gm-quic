use futures::{task::AtomicWaker, Future};
use std::{
    ops::Deref,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
};
use thiserror::Error;

/// All data sent in STREAM frames counts toward this limit.
#[derive(Debug, Default)]
pub struct Sender {
    total_sent: AtomicU64,
    max_data: AtomicU64,
    waker: AtomicWaker,
}

impl Sender {
    /// snd_wnd是对方协商时设置的，客户端一开始不知道服务端参数的情况下，
    /// 应该使用Default初始化为0，直至收到服务端的quic parameter或者MAX_DATA帧告知
    pub fn with_initial(snd_wnd: u64) -> Self {
        Self {
            total_sent: AtomicU64::new(0),
            max_data: AtomicU64::new(snd_wnd),
            waker: AtomicWaker::new(),
        }
    }

    /// Increasing Flow Control Limits
    pub fn incr_wnd(&self, max_data: u64) {
        // the new max_data != previous self.max_data, meaning fetch_max update successfully
        if max_data != self.max_data.fetch_max(max_data, Ordering::Release) {
            self.waker.wake();
        }
    }

    pub fn avaliable(&self) -> u64 {
        let total_sent = self.total_sent.load(Ordering::Acquire);
        let max_data = self.max_data.load(Ordering::Acquire);
        total_sent - max_data
    }

    /// Update the amount of data sent after each time data of 'amount' bytes is sent
    pub fn post_sent(&self, amount: usize) {
        // THINK: Do we need check total_sent + amount <= max_data? No, it will not happen,
        // because amount is calcucated less than max_data - total_sent
        self.total_sent.fetch_add(amount as u64, Ordering::Release);
    }

    pub fn register(&self, waker: &Waker) {
        self.waker.register(waker);
    }
}

#[derive(Debug, Clone, Copy, Error)]
#[error("Flow Control exceed {0} bytes on receiving")]
pub struct Overflow(usize);

#[derive(Debug, Default)]
pub struct Recver {
    total_rcvd: AtomicU64,
    max_data: AtomicU64,
    step: u64,
    is_closed: AtomicBool,
    waker: AtomicWaker,
}

impl Recver {
    pub fn with_initial(rcv_wnd: u64) -> Self {
        Self {
            total_rcvd: AtomicU64::new(0),
            max_data: AtomicU64::new(rcv_wnd),
            step: rcv_wnd / 2,
            is_closed: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    /// 必须是新数据，旧的重传的数据不算。至于是不是新数据，得等将数据包交付给各个流后，
    /// 由各个流判定是否新数据，将新数据量作為amount参数反馈。如：
    /// - 如接收新数据量仍没超过max_data则是ok
    /// - 如超过了max_data，则返回错误，该错误将导致quic的FLOW_CONTROL_ERROR
    pub fn on_rcvd_new(&self, amount: usize) -> Result<usize, Overflow> {
        debug_assert!(!self.is_closed.load(Ordering::Relaxed));

        self.total_rcvd.fetch_add(amount as u64, Ordering::Release);
        let total_rcvd = self.total_rcvd.load(Ordering::Acquire);
        let max_data = self.max_data.load(Ordering::Acquire);
        if total_rcvd <= max_data {
            if total_rcvd + self.step >= max_data {
                self.waker.wake();
            }
            Ok(amount)
        } else {
            Err(Overflow((total_rcvd - max_data) as usize))
        }
    }

    pub fn poll_incr_wnd(&self, cx: &mut Context<'_>) -> Poll<Option<u64>> {
        if self.is_closed.load(Ordering::Acquire) {
            Poll::Ready(None)
        } else {
            let max_data = self.max_data.load(Ordering::Acquire);
            let total_rcvd = self.total_rcvd.load(Ordering::Acquire);

            if total_rcvd + self.step >= max_data {
                self.max_data.fetch_add(self.step, Ordering::Release);
                Poll::Ready(Some(max_data + self.step))
            } else {
                self.waker.register(cx.waker());
                Poll::Pending
            }
        }
    }

    pub fn close(&self) {
        if !self.is_closed.swap(true, Ordering::Release) {
            // 精准地调用一次，可防范多次调用close导致的不必要的唤醒
            self.waker.wake();
        }
    }
}

#[derive(Debug, Default)]
pub struct FlowController {
    pub sender: Sender,
    pub recver: Recver,
}

impl FlowController {
    pub fn with_initial(snd_wnd: u64, rcv_wnd: u64) -> Self {
        Self {
            sender: Sender::with_initial(snd_wnd),
            recver: Recver::with_initial(rcv_wnd),
        }
    }
}

/// A sendable and receivable shared connection-level flow controller.
#[derive(Debug, Default, Clone)]
pub struct ArcFlowController(Arc<FlowController>);

impl ArcFlowController {
    pub fn with_initial(snd_wnd: u64, rcv_wnd: u64) -> Self {
        Self(Arc::new(FlowController::with_initial(snd_wnd, rcv_wnd)))
    }
}

impl Deref for ArcFlowController {
    type Target = FlowController;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ArcFlowController {
    /// 一旦有返回，需向对方发送一个MaxData帧，告知对面扩大接收窗口，避免不必要流量阻塞
    pub async fn need_incr_wnd(&self) -> NeedIncrWnd {
        NeedIncrWnd(self.clone())
    }
}

pub struct NeedIncrWnd(ArcFlowController);

impl Future for NeedIncrWnd {
    type Output = Option<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.recver.poll_incr_wnd(cx)
    }
}
