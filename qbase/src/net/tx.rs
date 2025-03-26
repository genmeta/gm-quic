use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Waker},
};

use derive_more::Deref;

use super::route::Pathway;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy,PartialEq, Eq)]
    pub struct Signals: u8 {
        const CONGESTION    = 1 << 0; // cc
        const FLOW_CONTROL  = 1 << 1; // flow
        const TRANSPORT     = 1 << 2; // ack/retran/reliable....
        const WRITTEN       = 1 << 3; // fresh stream
        const CONNECTION_ID = 1 << 4; // cid
        const CREDIT        = 1 << 5; // aa
        const KEYS          = 1 << 6; // key(no waker in SendWaker)
        const PING          = 1 << 7; // packet which contains ping frames only
    }
}

#[derive(Default, Debug)]
pub struct SendWaker {
    waker: Option<Waker>,
    // Signals 对应的bit设置为1意为该位的条件已经满足，为0表示需要该条件满足
    state: u8,
}

impl SendWaker {
    pub fn new() -> Self {
        Self::default()
    }

    const WAITING: u8 = 0;

    pub fn wait_for(&mut self, cx: &mut Context, signals: Signals) {
        if self.state & signals.bits() == 0 {
            self.state = !signals.bits();
            match self.waker.as_ref() {
                Some(old_waker) if old_waker.will_wake(cx.waker()) => {}
                _ => self.waker = Some(cx.waker().clone()),
            }
        } else {
            self.state = Self::WAITING;
            cx.waker().wake_by_ref();
        }
    }

    fn wake_by(&mut self, signals: Signals) {
        if self.state & signals.bits() != signals.bits() {
            if let Some(waker) = self.waker.take() {
                self.state = Self::WAITING;
                waker.wake();
                return;
            }
        }
        self.state |= signals.bits();
    }
}

unsafe impl Send for SendWaker {}
unsafe impl Sync for SendWaker {}

#[derive(Debug, Default, Clone)]
pub struct ArcSendWaker(Arc<Mutex<SendWaker>>);

impl ArcSendWaker {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(SendWaker::new())))
    }

    pub fn wait_for(&self, cx: &mut Context, signals: Signals) {
        self.0.lock().unwrap().wait_for(cx, signals);
    }

    pub fn wake_by(&self, signals: Signals) {
        self.0.lock().unwrap().wake_by(signals);
    }
}

/// connection level send wakers
#[derive(Debug, Default)]
pub struct SendWakers(RwLock<HashMap<Pathway, ArcSendWaker>>);

impl SendWakers {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn insert(&self, pathway: Pathway, waker: &ArcSendWaker) {
        self.0
            .write()
            .unwrap()
            .entry(pathway)
            .or_insert_with(|| waker.clone());
    }

    pub fn remove(&self, pathway: &Pathway) {
        self.0.write().unwrap().remove(pathway);
    }

    pub fn wake_all_by(&self, signals: Signals) {
        self.0
            .read()
            .unwrap()
            .values()
            .for_each(|waker| waker.wake_by(signals));
    }
}

#[derive(Default, Debug, Clone, Deref)]
pub struct ArcSendWakers(Arc<SendWakers>);

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering::*},
        task::Poll,
    };

    impl ArcSendWaker {
        fn state(&self) -> u8 {
            self.0.lock().unwrap().state
        }
    }

    use super::*;

    #[tokio::test]
    async fn single_condition() {
        let waker = ArcSendWaker::new();
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
        let waker = ArcSendWaker::new();
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

        let wait_for_all_cond_state = !Signals::all().bits();

        waker.wake_by(Signals::FLOW_CONTROL);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // woken
        assert_eq!(waker.state(), wait_for_all_cond_state);

        waker.wake_by(Signals::TRANSPORT);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 3); // woken
        assert_eq!(waker.state(), wait_for_all_cond_state);

        waker.wake_by(Signals::CONGESTION);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 4); // woken
        assert_eq!(waker.state(), wait_for_all_cond_state);
    }

    #[tokio::test]
    async fn wake_before_register() {
        let waker = ArcSendWaker::new();
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

        let wait_for_quota_state = !Signals::CONGESTION.bits();

        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // woken
        assert_eq!(waker.state(), wait_for_quota_state);
    }

    #[tokio::test]
    async fn state_change() {
        let waker = ArcSendWaker::new();
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

        let wait_for_all_cond_state = !Signals::all().bits();

        let wait_for_quota_state = !(Signals::CONGESTION | Signals::TRANSPORT).bits();

        let wait_for_data_state = !Signals::TRANSPORT.bits();

        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // woken(1 = enter)
        assert_eq!(waker.state(), wait_for_all_cond_state);

        waker.wake_by(Signals::TRANSPORT); // all condition will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 3); // woken(3 = enter+wake+enter)
        assert_eq!(waker.state(), wait_for_quota_state);

        waker.wake_by(Signals::CONGESTION); // quota\data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 5); // woken(5 = enter+wake+enter+wake+enter)
        assert_eq!(waker.state(), wait_for_data_state);

        waker.wake_by(Signals::CONGESTION); // only data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 5); // not woken

        waker.wake_by(Signals::FLOW_CONTROL); // only data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 5); // not woken

        waker.wake_by(Signals::TRANSPORT); // only data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 6); // woken(6 = [enter+wake]*3)
        assert_eq!(waker.state(), wait_for_data_state);
    }

    #[tokio::test]
    async fn mult_wake_signals() {
        let waker = ArcSendWaker::new();
        let woken_times = Arc::new(AtomicUsize::new(0));

        tokio::spawn({
            let waker = waker.clone();
            let wake_times = woken_times.clone();
            core::future::poll_fn(move |cx| {
                wake_times.fetch_add(1, Release);
                waker.wait_for(cx, Signals::TRANSPORT);
                Poll::<()>::Pending
            })
        });

        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); //  wake
        assert_eq!(waker.state(), !Signals::TRANSPORT.bits());

        waker.wake_by(Signals::TRANSPORT);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // enter + wake
        assert_eq!(waker.state(), !Signals::TRANSPORT.bits());

        waker.wake_by(Signals::CONGESTION | Signals::TRANSPORT);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 3); // enter + wake * 2
        assert_eq!(waker.state(), !Signals::TRANSPORT.bits());
    }
}
