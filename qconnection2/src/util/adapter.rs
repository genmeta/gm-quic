use core::future::Future;
use std::ops::DerefMut;

use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard};

enum SharedOnceInner<F: Future> {
    Pending { future: F },
    Completed { output: F::Output },
}

pub struct SharedOnce<F: Future>(Mutex<SharedOnceInner<F>>);

impl<F: Future> SharedOnce<F> {
    pub fn from_future(future: F) -> Self {
        Self(Mutex::new(SharedOnceInner::Pending { future }))
    }

    pub async fn get_or_init(&self) -> MappedMutexGuard<'_, F::Output>
    where
        F: Unpin,
    {
        // 这样的实现只能一个个唤醒，但是胜在实现简单，切合使用场景
        let mut inner = self.0.lock().await;

        if let SharedOnceInner::Pending { future } = inner.deref_mut() {
            let output = future.await;
            *inner = SharedOnceInner::Completed { output };
        }
        MutexGuard::map(inner, |inner| match inner {
            SharedOnceInner::Pending { .. } => unreachable!(),
            SharedOnceInner::Completed { output } => output,
        })
    }
}
