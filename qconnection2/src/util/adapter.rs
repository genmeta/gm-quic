use core::future::Future;
use std::ops::DerefMut;

use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard};

enum ConcurrentInner<F: Future> {
    Pending { future: F },
    Completed { output: F::Output },
}

pub struct Concurrent<F: Future>(Mutex<ConcurrentInner<F>>);

impl<F: Future> Concurrent<F> {
    pub fn new(future: F) -> Self {
        Self(Mutex::new(ConcurrentInner::Pending { future }))
    }

    pub async fn get(&self) -> MappedMutexGuard<'_, F::Output>
    where
        F: Unpin,
    {
        // 这样的实现只能一个个唤醒，但是胜在实现简单，切合使用场景
        let mut inner = self.0.lock().await;

        if let ConcurrentInner::Pending { future } = inner.deref_mut() {
            let output = future.await;
            *inner = ConcurrentInner::Completed { output };
        }
        MutexGuard::map(inner, |inner| match inner {
            ConcurrentInner::Pending { .. } => unreachable!(),
            ConcurrentInner::Completed { output } => output,
        })
    }
}
