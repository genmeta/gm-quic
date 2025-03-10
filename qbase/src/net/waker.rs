use std::{
    cell::UnsafeCell,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering::*},
    },
    task::{Context, Waker},
};

use dashmap::DashMap;
use deref_derive::Deref;

use super::Pathway;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy,PartialEq, Eq)]
    pub struct Signals: u8 {
        const CONGESTION  = 1 << 0; // cc
        const FLOW_CONTROL = 1 << 1; // flow
        const TRANSPORT = 1 << 2; // ack/retran/reliable....
        const WRITTEN = 1 << 3; // ack/retran/reliable....
        const CONNECTION_ID = 1 << 4; // cid
        const CREDIT = 1 << 5; // aa
        const KEYS  = 1 << 6; // key(no waker in SendWaker)
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
    const WAITING: u32 = 0;

    pub fn wait_for(&self, cx: &mut Context, signals: Signals) {
        // lock and set the no-wait condition bit to true
        let registering_state = Self::REGISTERING | !(signals.bits() as u32);
        // only one thread will get the lock
        match self.state.swap(registering_state, AcqRel) {
            // lock is got, and the waking state is not registered
            waiting if waiting & Self::REGISTERING == 0 && waiting & signals.bits() as u32 == 0 => {
                unsafe {
                    match &*self.waker.get() {
                        Some(old_waker) if old_waker.will_wake(cx.waker()) => {}
                        _ => *self.waker.get() = Some(cx.waker().clone()),
                    }
                }

                // clear the lock bit
                match self.state.fetch_and(!Self::REGISTERING, AcqRel) {
                    // the condition is met when the waker may be none, wake the task here
                    woken if woken & signals.bits() as u32 != 0 => {
                        self.state.store(Self::WAITING, Release);
                        let waker = unsafe { (*self.waker.get()).take().unwrap() };
                        waker.wake();
                    }
                    _ => {}
                }
            }
            // lock is got, and the waking state is already registered
            woken if woken & Self::REGISTERING == 0 && woken & signals.bits() as u32 != 0 => {
                // clear the lock bit
                self.state.store(Self::WAITING, Release);
                cx.waker().wake_by_ref();
            }
            // the lock is acquired by other task
            _other_registering => {}
        }
    }

    fn wake_by(&self, signals: Signals) {
        // set the condition bit to true
        match self.state.fetch_or(signals.bits() as u32, AcqRel) {
            // if there is no other thread registering, and the condition is met
            waiting if waiting & Self::REGISTERING == 0 && waiting & signals.bits() as u32 == 0 => {
                if let Some(waker) = unsafe { (*self.waker.get()).take() } {
                    self.state.swap(Self::WAITING, AcqRel);
                    waker.wake();
                }
                // the condition is in need but the waker is none: woken by other task
            }
            // if registering: wake will be handled by `Self::wait`
            // if condition is not in need: nothing happens
            _not_woken => {}
        }
    }
}

unsafe impl Send for SendWaker {}
unsafe impl Sync for SendWaker {}

#[derive(Debug, Default, Clone)]
pub struct ArcSendWaker(Arc<SendWaker>);

impl ArcSendWaker {
    pub fn new() -> Self {
        Self(Arc::new(SendWaker::new()))
    }

    pub fn wait_for(&self, cx: &mut Context, signals: Signals) {
        self.0.wait_for(cx, signals);
    }

    pub fn wake_by(&self, signals: Signals) {
        self.0.wake_by(signals);
    }
}

/// connection level send wakers
#[derive(Debug, Default)]
pub struct SendWakers(DashMap<Pathway, ArcSendWaker>);

impl SendWakers {
    pub fn new() -> Self {
        Self(DashMap::new())
    }

    pub fn insert(&self, pathway: Pathway, waker: &ArcSendWaker) {
        self.0.entry(pathway).or_insert_with(|| waker.clone());
    }

    pub fn remove(&self, pathway: &Pathway) {
        self.0.remove(pathway);
    }

    pub fn wake_all_by(&self, signals: Signals) {
        for waker in self.0.iter() {
            waker.wake_by(signals);
        }
    }
}

#[derive(Default, Debug, Clone, Deref)]
pub struct ArcSendWakers(Arc<SendWakers>);

#[cfg(test)]
mod tests {
    use std::{sync::atomic::AtomicUsize, task::Poll};

    use super::*;

    #[tokio::test]
    async fn single_condition() {
        let waker = Arc::new(SendWaker::new());
        let woken_times = Arc::new(AtomicUsize::new(0));

        tokio::spawn({
            let waker = waker.clone();
            let wake_times = woken_times.clone();
            core::future::poll_fn(move |cx| {
                wake_times.fetch_add(1, Release);
                waker.wait_for(cx, Signals::CONGESTION);
                Poll::<()>::Pending
            })
        });

        waker.wake_by(Signals::FLOW_CONTROL);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // not woken

        waker.wake_by(Signals::TRANSPORT);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // not woken

        waker.wake_by(Signals::CONGESTION);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // woken
    }

    #[tokio::test]
    async fn all_condition() {
        let waker = Arc::new(SendWaker::new());
        let woken_times = Arc::new(AtomicUsize::new(0));

        tokio::spawn({
            let waker = waker.clone();
            let wake_times = woken_times.clone();
            core::future::poll_fn(move |cx| {
                wake_times.fetch_add(1, Release);
                waker.wait_for(cx, Signals::all());
                Poll::<()>::Pending
            })
        });

        let wait_for_all_cond_state = !SendWaker::REGISTERING & !(Signals::all().bits() as u32);

        waker.wake_by(Signals::FLOW_CONTROL);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // woken
        assert_eq!(waker.state.load(Acquire), wait_for_all_cond_state);

        waker.wake_by(Signals::TRANSPORT);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 3); // woken
        assert_eq!(waker.state.load(Acquire), wait_for_all_cond_state);

        waker.wake_by(Signals::CONGESTION);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 4); // woken
        assert_eq!(waker.state.load(Acquire), wait_for_all_cond_state);
    }

    #[tokio::test]
    async fn wake_before_register() {
        let waker = Arc::new(SendWaker::new());
        let woken_times = Arc::new(AtomicUsize::new(0));

        waker.wake_by(Signals::CONGESTION); // pre set woken state

        tokio::spawn({
            let waker = waker.clone();
            let wake_times = woken_times.clone();
            core::future::poll_fn(move |cx| {
                wake_times.fetch_add(1, Release);
                waker.wait_for(cx, Signals::CONGESTION);
                Poll::<()>::Pending
            })
        });

        let wait_for_quota_state = !SendWaker::REGISTERING & !(Signals::CONGESTION.bits() as u32);

        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // woken
        assert_eq!(waker.state.load(Acquire), wait_for_quota_state);
    }

    #[tokio::test]
    async fn state_change() {
        let waker = Arc::new(SendWaker::new());
        let woken_times = Arc::new(AtomicUsize::new(0));

        tokio::spawn({
            let waker = waker.clone();
            let wake_times = woken_times.clone();

            let wait_for = async move |r#for| {
                core::future::poll_fn(|cx| {
                    let wake_times = wake_times.fetch_add(1, Release);
                    waker.wait_for(cx, r#for);
                    if wake_times % 2 == 1 {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            };

            async move {
                wait_for(Signals::all()).await;
                wait_for(Signals::CONGESTION | Signals::TRANSPORT).await;
                wait_for(Signals::TRANSPORT).await;
            }
        });

        let wait_for_all_cond_state = !SendWaker::REGISTERING & !(Signals::all().bits() as u32);

        let wait_for_quota_state =
            !SendWaker::REGISTERING & !((Signals::CONGESTION | Signals::TRANSPORT).bits() as u32);

        let wait_for_data_state = !SendWaker::REGISTERING & !(Signals::TRANSPORT.bits() as u32);

        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // woken(1 = enter)
        assert_eq!(waker.state.load(Acquire), wait_for_all_cond_state);

        waker.wake_by(Signals::TRANSPORT); // all condition will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 3); // woken(3 = enter+wake+enter)
        assert_eq!(waker.state.load(Acquire), wait_for_quota_state);

        waker.wake_by(Signals::CONGESTION); // quota\data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 5); // woken(5 = enter+wake+enter+wake+enter)
        assert_eq!(waker.state.load(Acquire), wait_for_data_state);

        waker.wake_by(Signals::CONGESTION); // only data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 5); // not woken

        waker.wake_by(Signals::FLOW_CONTROL); // only data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 5); // not woken

        waker.wake_by(Signals::TRANSPORT); // only data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 6); // woken(6 = [enter+wake]*3)
        assert_eq!(waker.state.load(Acquire), wait_for_data_state);
    }
}
