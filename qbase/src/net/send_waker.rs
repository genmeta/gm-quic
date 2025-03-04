use std::{
    cell::UnsafeCell,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering::*},
    },
    task::{Context, Waker},
};

use dashmap::DashMap;

use super::Pathway;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct SendLimiter: u8 {
        const INSUFFICIENT_QUOTA = 1 << 0; // cc
        const FLOW_CONTROL       = 1 << 1; // flow
        const DATA_UNAVAILABLE   = 1 << 2; // ack/retran/reliable....
        const NO_CONNECTION_ID   = 1 << 3; // cid
        const CREDIT_EXHAUSTED   = 1 << 4; // aa
    }
}

#[derive(Default, Debug)]
pub struct SendWaker {
    waker: UnsafeCell<Option<Waker>>,
    state: AtomicU32,
}

impl SendWaker {
    pub fn new() -> Self {
        Self::default()
    }

    // LoadPacketError 对应的bit设置为1意为该位的条件已经满足，为0表示需要该条件满足
    // 最高位表示正在注册waker，类似AtomicWaker的注册状态
    const REGISTERING: u32 = 1 << (u32::MAX.leading_ones() - 1);
    const WAITING: u32 = !Self::REGISTERING;

    pub fn wait(&self, cond: SendLimiter, cx: &mut Context) {
        // lock and set the no-wait condition bit to true
        let registering_state = Self::REGISTERING | !(cond.bits() as u32);
        // only one thread will get the lock
        match self.state.swap(registering_state, AcqRel) {
            // lock is got, and the waking state is not registered
            waiting if waiting & Self::REGISTERING == 0 && waiting & cond.bits() as u32 == 0 => {
                unsafe {
                    match &*self.waker.get() {
                        Some(old_waker) if old_waker.will_wake(cx.waker()) => {}
                        _ => *self.waker.get() = Some(cx.waker().clone()),
                    }
                }

                // clear the lock bit
                match self.state.fetch_and(!Self::REGISTERING, AcqRel) {
                    // the condition is met when the waker may be none, wake the task here
                    woken if woken & cond.bits() as u32 != 0 => {
                        let waker = unsafe { (*self.waker.get()).take().unwrap() };
                        self.state.store(Self::WAITING, Release);
                        waker.wake();
                    }
                    _ => {}
                }
            }
            // lock is got, and the waking state is already registered
            waking if waking & Self::REGISTERING == 0 && waking & cond.bits() as u32 != 0 => {
                cx.waker().wake_by_ref();
                // clear the lock bit
                self.state.store(Self::WAITING, Release);
            }
            // the lock is acquired by other task
            _other_registering => {}
        }
    }

    fn wake(&self, by: SendLimiter) {
        // set the condition bit to true
        match self.state.fetch_or(by.bits() as u32, AcqRel) {
            // if there is no other thread registering, and the condition is met
            waking if waking & Self::REGISTERING == 0 && waking & by.bits() as u32 == 0 => {
                if let Some(waker) = unsafe { (*self.waker.get()).take() } {
                    waker.wake();
                    self.state.swap(Self::WAITING, AcqRel);
                }
                // the condition is in need but the waker is none: woken by other task
            }
            // if registering: wake will be handled by `Self::wait`
            // if condition is not in need: nothing happens
            _registring => {}
        }
    }
}

unsafe impl Send for SendWaker {}
unsafe impl Sync for SendWaker {}

pub struct LimiterWaker<const LIMITER: u8>(Arc<SendWaker>);

impl<const LIMITER: u8> LimiterWaker<LIMITER> {
    pub fn wake(&self) {
        self.0
            .wake(SendLimiter::from_bits(LIMITER).expect("invalid limiter"));
    }
}

pub type QuotaWaker = LimiterWaker<{ SendLimiter::INSUFFICIENT_QUOTA.bits() }>;
pub type FlowWaker = LimiterWaker<{ SendLimiter::FLOW_CONTROL.bits() }>;
pub type DataWaker = LimiterWaker<{ SendLimiter::DATA_UNAVAILABLE.bits() }>;
pub type ConnectionIdWaker = LimiterWaker<{ SendLimiter::NO_CONNECTION_ID.bits() }>;
pub type CreditWaker = LimiterWaker<{ SendLimiter::CREDIT_EXHAUSTED.bits() }>;

impl SendWaker {
    pub fn quota_waker(self: &Arc<Self>) -> QuotaWaker {
        LimiterWaker(self.clone())
    }

    pub fn flow_waker(self: &Arc<Self>) -> FlowWaker {
        LimiterWaker(self.clone())
    }

    pub fn data_waker(self: &Arc<Self>) -> DataWaker {
        LimiterWaker(self.clone())
    }

    pub fn connection_id_waker(self: &Arc<Self>) -> ConnectionIdWaker {
        LimiterWaker(self.clone())
    }

    pub fn credit_waker(self: &Arc<Self>) -> CreditWaker {
        LimiterWaker(self.clone())
    }
}

/// connection level send wakers
#[derive(Debug, Default)]
pub struct SendWakers(DashMap<Pathway, Arc<SendWaker>>);

impl SendWakers {
    pub fn new() -> Self {
        Self(DashMap::new())
    }

    pub fn insert(&self, pathway: Pathway, waker: &Arc<SendWaker>) {
        self.0.entry(pathway).or_insert_with(|| waker.clone());
    }

    pub fn remove(&self, pathway: &Pathway) {
        self.0.remove(pathway);
    }
}

pub struct LimiterWakers<const LIMITER: u8>(Arc<SendWakers>);

impl<const LIMITER: u8> LimiterWakers<LIMITER> {
    pub fn wake_all(&self) {
        for waker in self.0.0.iter() {
            waker.wake(SendLimiter::from_bits(LIMITER).expect("invalid limiter"));
        }
    }
}

pub type FlowWakers = LimiterWakers<{ SendLimiter::FLOW_CONTROL.bits() }>;
pub type DataWakers = LimiterWakers<{ SendLimiter::DATA_UNAVAILABLE.bits() }>;

impl SendWakers {
    pub fn flow_wakers(self: &Arc<Self>) -> FlowWakers {
        LimiterWakers(self.clone())
    }

    pub fn data_wakers(self: &Arc<Self>) -> DataWakers {
        LimiterWakers(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::atomic::AtomicUsize, task::Poll};

    use super::*;

    #[tokio::test]
    async fn single_condition() {
        let wakers = Arc::new(SendWaker::new());
        let woken_times = Arc::new(AtomicUsize::new(0));

        tokio::spawn({
            let wakers = wakers.clone();
            let wake_times = woken_times.clone();
            core::future::poll_fn(move |cx| {
                wake_times.fetch_add(1, Release);
                wakers.wait(SendLimiter::INSUFFICIENT_QUOTA, cx);
                Poll::<()>::Pending
            })
        });

        wakers.flow_waker().wake();
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // not woken

        wakers.data_waker().wake();
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // not woken

        wakers.quota_waker().wake();
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // woken
    }

    #[tokio::test]
    async fn all_condition() {
        let wakers = Arc::new(SendWaker::new());
        let woken_times = Arc::new(AtomicUsize::new(0));

        tokio::spawn({
            let wakers = wakers.clone();
            let wake_times = woken_times.clone();
            core::future::poll_fn(move |cx| {
                wake_times.fetch_add(1, Release);
                wakers.wait(SendLimiter::all(), cx);
                Poll::<()>::Pending
            })
        });

        let wait_for_all_cond_state = !SendWaker::REGISTERING & !(SendLimiter::all().bits() as u32);

        wakers.flow_waker().wake();
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // woken
        assert_eq!(wakers.state.load(Acquire), wait_for_all_cond_state);

        wakers.data_waker().wake();
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 3); // woken
        assert_eq!(wakers.state.load(Acquire), wait_for_all_cond_state);

        wakers.quota_waker().wake();
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 4); // woken
        assert_eq!(wakers.state.load(Acquire), wait_for_all_cond_state);
    }

    #[tokio::test]
    async fn wake_before_register() {
        let wakers = Arc::new(SendWaker::new());
        let woken_times = Arc::new(AtomicUsize::new(0));

        wakers.quota_waker().wake(); // pre set woken state

        tokio::spawn({
            let wakers = wakers.clone();
            let wake_times = woken_times.clone();
            core::future::poll_fn(move |cx| {
                wake_times.fetch_add(1, Release);
                wakers.wait(SendLimiter::INSUFFICIENT_QUOTA, cx);
                Poll::<()>::Pending
            })
        });

        let wait_for_quota_state =
            !SendWaker::REGISTERING & !(SendLimiter::INSUFFICIENT_QUOTA.bits() as u32);

        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // woken
        assert_eq!(wakers.state.load(Acquire), wait_for_quota_state);
    }

    #[tokio::test]
    async fn state_change() {
        let wakers = Arc::new(SendWaker::new());
        let woken_times = Arc::new(AtomicUsize::new(0));

        tokio::spawn({
            let wakers = wakers.clone();
            let wake_times = woken_times.clone();

            let wait_for = async move |r#for| {
                core::future::poll_fn(|cx| {
                    let wake_times = wake_times.fetch_add(1, Release);
                    wakers.wait(r#for, cx);
                    if wake_times % 2 == 1 {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            };

            async move {
                wait_for(SendLimiter::all()).await;
                wait_for(SendLimiter::INSUFFICIENT_QUOTA | SendLimiter::DATA_UNAVAILABLE).await;
                wait_for(SendLimiter::DATA_UNAVAILABLE).await;
            }
        });

        let wait_for_all_cond_state = !SendWaker::REGISTERING & !(SendLimiter::all().bits() as u32);

        let wait_for_quota_state = !SendWaker::REGISTERING
            & !((SendLimiter::INSUFFICIENT_QUOTA | SendLimiter::DATA_UNAVAILABLE).bits() as u32);

        let wait_for_data_state =
            !SendWaker::REGISTERING & !(SendLimiter::DATA_UNAVAILABLE.bits() as u32);

        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // woken(1 = enter)
        assert_eq!(wakers.state.load(Acquire), wait_for_all_cond_state);

        wakers.data_waker().wake(); // all condition will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 3); // woken(3 = enter+wake+enter)
        assert_eq!(wakers.state.load(Acquire), wait_for_quota_state);

        wakers.quota_waker().wake(); // quota\data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 5); // woken(5 = enter+wake+enter+wake+enter)
        assert_eq!(wakers.state.load(Acquire), wait_for_data_state);

        wakers.quota_waker().wake(); // only data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 5); // not woken

        wakers.flow_waker().wake(); // only data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 5); // not woken

        wakers.data_waker().wake(); // only data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 6); // woken(6 = [enter+wake]*3)
        assert_eq!(wakers.state.load(Acquire), wait_for_data_state);
    }
}
