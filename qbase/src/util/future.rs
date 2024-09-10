use std::{
    ops::Deref,
    sync::{Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

#[derive(Debug, Default, Clone)]
pub(crate) enum RawFuture<T> {
    #[default]
    None,
    Demand(Waker),
    Ready(T),
}

#[derive(Debug)]
pub struct Future<T> {
    state: Mutex<RawFuture<T>>,
}

impl<T: Clone> Future<T> {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn with(item: T) -> Self {
        Self {
            state: Mutex::new(RawFuture::Ready(item)),
        }
    }

    pub(crate) fn state(&self) -> MutexGuard<RawFuture<T>> {
        self.state.lock().unwrap()
    }

    #[inline]
    pub fn assign(&self, item: T) -> Result<(), T> {
        let mut state = self.state();
        match state.deref() {
            RawFuture::None => {}
            RawFuture::Demand(waker) => waker.wake_by_ref(),
            RawFuture::Ready(_) => return Err(item),
        }
        *state = RawFuture::Ready(item);
        Ok(())
    }

    #[inline]
    pub fn poll_get(&self, cx: &mut Context<'_>) -> Poll<T> {
        let mut raw_future = self.state();
        match raw_future.deref() {
            RawFuture::None => {
                *raw_future = RawFuture::Demand(cx.waker().clone());
                Poll::Pending
            }
            RawFuture::Ready(item) => Poll::Ready(item.clone()),
            RawFuture::Demand(waker) => {
                if !waker.will_wake(cx.waker()) {
                    drop(raw_future);
                    panic!("trying to wait on a future from multiple tasks");
                }
                Poll::Pending
            }
        }
    }

    pub fn try_get(&self) -> Option<T> {
        match self.state().deref() {
            RawFuture::Ready(item) => Some(item.clone()),
            _ => None,
        }
    }

    #[inline]
    pub fn get(&self) -> Get<'_, T> {
        Get(self)
    }
}

impl<T> Default for Future<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(RawFuture::None),
        }
    }
}

pub struct Get<'f, T: Clone>(&'f Future<T>);

impl<T: Clone> Unpin for Get<'_, T> {}

impl<T: Clone> std::future::Future for Get<'_, T> {
    type Output = T;

    #[inline]
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_get(cx)
    }
}

impl<T: Clone> Drop for Get<'_, T> {
    #[inline]
    fn drop(&mut self) {
        let mut raw_future = self.0.state();
        if let RawFuture::Demand(waker) = raw_future.deref() {
            // If the Value dropped because the task is dropped, wake is noop.
            // If the Value dropped bacause panic(racing), this is wake up another task.
            waker.wake_by_ref();
            *raw_future = RawFuture::None;
        }
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use tokio::sync::Notify;

    use super::*;

    #[test]
    fn new() {
        let future = Future::new();
        assert_eq!(future.try_get(), None);
        assert_eq!(future.assign("Hello world"), Ok(()));
        assert_eq!(future.try_get(), Some("Hello world"));

        let future = Future::with("Hello World");
        assert_eq!(future.try_get(), Some("Hello World"));
        assert_eq!(future.assign("Hello world"), Err("Hello world"));
    }

    #[tokio::test]
    async fn wait() {
        let future = Arc::new(Future::<&str>::new());
        let write = Arc::new(Notify::new());
        let task = tokio::spawn({
            let future = future.clone();
            let write = write.clone();
            async move {
                core::future::poll_fn(|cx| {
                    assert_eq!(future.poll_get(cx), Poll::Pending);
                    write.notify_one();
                    *future.state() = RawFuture::None;

                    Poll::Ready(())
                })
                .await;

                assert_eq!(future.get().await, "Hello world");
            }
        });

        write.notified().await;
        assert_eq!(future.try_get(), None);
        assert_eq!(future.assign("Hello world"), Ok(()));

        task.await.unwrap();
    }

    #[tokio::test]
    async fn mpsc() {
        let fufure = Arc::new(Future::<&str>::new());
        let task_panic = Arc::new(Notify::new());
        let task_finish = Arc::new(Notify::new());

        let task1 = tokio::spawn({
            let future = fufure.clone();
            let task_panic = task_panic.clone();
            let task_finish = task_finish.clone();
            async move {
                let result = tokio::spawn(async move {
                    let value = future.get().await;
                    task_finish.notify_one();
                    value
                })
                .await;
                task_panic.notify_one();
                result
            }
        });

        let task2 = tokio::spawn({
            let future = fufure.clone();
            let task_panic = task_panic.clone();
            let task_finish = task_finish.clone();
            async move {
                let result = tokio::spawn(async move {
                    let value = future.get().await;
                    task_finish.notify_one();
                    value
                })
                .await;
                task_panic.notify_one();
                result
            }
        });

        task_panic.notified().await;
        assert_eq!(fufure.assign("Hello world"), Ok(()));
        task_finish.notified().await;

        match tokio::try_join!(task1, task2) {
            Ok((Ok("Hello world"), Err(..))) => {}
            Ok((Err(..), Ok("Hello world"))) => {}
            e => panic!("unexpected result: {e:?}"),
        }
    }
}
