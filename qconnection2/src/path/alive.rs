use core::future::Future;
use std::sync::{Arc, Mutex};

use futures::task::AtomicWaker;

pub struct LastReceiveTime {
    last: Mutex<tokio::time::Instant>,
    wake: AtomicWaker,
}

impl LastReceiveTime {
    pub fn now() -> Self {
        Self {
            last: Mutex::new(tokio::time::Instant::now()),
            wake: AtomicWaker::new(),
        }
    }

    pub async fn timeout(&self, duration: tokio::time::Duration) {
        let deadline = *self.last.lock().unwrap() + duration;
        let sleep = tokio::time::sleep(deadline - tokio::time::Instant::now());
        tokio::pin!(sleep);
        core::future::poll_fn(|cx| {
            self.wake.register(cx.waker());
            let deadline = *self.last.lock().unwrap() + duration;
            sleep.as_mut().reset(deadline);
            sleep.as_mut().poll(cx)
        })
        .await;
    }

    pub fn get(&self) -> tokio::time::Instant {
        *self.last.lock().unwrap()
    }

    pub fn update(&self) {
        *self.last.lock().unwrap() = tokio::time::Instant::now();
        self.wake.wake();
    }
}

pub struct Heartbeat {
    path: Arc<super::Path>,
}

impl super::Path {
    pub fn new_heartbeat(self: &Arc<Self>) -> Heartbeat {
        Heartbeat { path: self.clone() }
    }
}

impl Heartbeat {
    pub fn begin_keeping_alive<F>(self, on_inactive: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce() + Send + 'static,
    {
        tokio::spawn(async move {
            let inactive_time = tokio::time::Duration::from_secs(30);

            let mut last_rcvd = self.path.last_recv_time.get();
            let mut times = 0;
            loop {
                self.path.last_recv_time.timeout(inactive_time).await;
                // TODO: send ping
                let new_last_rcvd = self.path.last_recv_time.get();
                if new_last_rcvd != last_rcvd {
                    last_rcvd = new_last_rcvd;
                    times = 0;
                } else {
                    times += 1;
                    if times == 3 {
                        (on_inactive)();
                        return;
                    }
                }
            }
        })
    }
}
