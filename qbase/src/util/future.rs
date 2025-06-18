use std::{
    ops::{Deref, DerefMut},
    sync::{Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    vec,
};

#[derive(Debug, Clone)]
pub(crate) enum FutureState<T> {
    Demand(Vec<Waker>),
    Ready(T),
}

impl<T> Default for FutureState<T> {
    fn default() -> Self {
        Self::Demand(vec![])
    }
}

#[derive(Debug)]
pub struct ReadyFuture<'f, T>(MutexGuard<'f, FutureState<T>>);

impl<T> Deref for ReadyFuture<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self.0.deref() {
            FutureState::Demand(..) => unreachable!(),
            FutureState::Ready(item) => item,
        }
    }
}

/// A value which will be resolved in the future.
///
/// Be different with the [`futures::Future`], this is a value not a computation.
///
/// The task can attempt to get the value synchronously by calling [`try_get`], or asynchronously by
/// calling [`get`]. There are also a [`poll_get`] method for the task to poll the value. Read their
/// document for more details about the behavior.
///
/// # Examples
/// ``` rust, no_run
/// # use qbase::util::Future;
/// # async fn some_work() -> &'static str { "Hello World" }
/// # async fn test() {
/// use std::sync::Arc;
///
/// let fut = Arc::new(Future::new());
/// let t1 = tokio::spawn({
///     let fut = fut.clone();
///     async move {
///         assert_eq!(*fut.get().await, "Hello world");
///         // the value can be get multiple times
///         assert_eq!(*fut.get().await, "Hello world");
///         assert_eq!(*fut.get().await, "Hello world");
///     }
/// });
///
/// let t2 = tokio::spawn({
///     let fut = fut.clone();
///     async move {
///         // do some work to get the value
///         let value = some_work().await;
///         fut.set(value);
///
///         // the new value will replace the old value
///         assert_eq!(fut.set("Hi World"), Some("Hello, World"));
///     }
/// });
///
/// _ = tokio::join!(t1, t2);
/// # }
///
/// ```
///
///
/// [`get`]: Future::get
/// [`try_get`]: Future::try_get
/// [`poll_get`]: Future::poll_get
#[derive(Debug)]
pub struct Future<T> {
    state: Mutex<FutureState<T>>,
}

impl<T> Future<T> {
    /// Create a new empty [`Future`].
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a new [`Future`] with the given value in it.
    #[inline]
    pub fn with(item: T) -> Self {
        Self {
            state: Mutex::new(FutureState::Ready(item)),
        }
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, FutureState<T>> {
        self.state.lock().unwrap()
    }

    /// Set the value to the [`Future`].
    ///
    /// Return the old value as [`Some`] if the future is already set.
    #[inline]
    pub fn set(&self, item: T) -> Option<T> {
        match std::mem::replace(self.state().deref_mut(), FutureState::Ready(item)) {
            FutureState::Demand(wakers) => {
                wakers.into_iter().for_each(|waker| waker.wake_by_ref());
                None
            }
            FutureState::Ready(old) => Some(old),
        }
    }

    /// Poll the value of the [`Future`].
    ///
    /// If the value is ready, the value will be returned as [`Poll::Ready`]. If the value is not
    /// ready, this method will return [`Poll::Pending`] and the waker will be stored.
    #[inline]
    pub fn poll_get(&self, cx: &mut Context<'_>) -> Poll<ReadyFuture<'_, T>> {
        let mut state = self.state();
        match state.deref_mut() {
            FutureState::Demand(wakers) => {
                wakers.push(cx.waker().clone());
                Poll::Pending
            }
            FutureState::Ready(..) => Poll::Ready(ReadyFuture(state)),
        }
    }

    /// Try to get the value of the [`Future`].
    ///
    /// If the value is ready, the value will be returned as [`Some`]. If the value is not ready, this
    /// method will return [`None`].
    pub fn try_get(&self) -> Option<ReadyFuture<'_, T>> {
        let state = self.state();
        match state.deref() {
            FutureState::Demand(..) => None,
            FutureState::Ready(_) => Some(ReadyFuture(state)),
        }
    }

    /// Get the value of the [`Future`] asynchronously.
    #[inline]
    pub async fn get(&self) -> ReadyFuture<'_, T> {
        std::future::poll_fn(|cx| self.poll_get(cx)).await
    }
}

impl<T> Default for Future<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(Default::default()),
        }
    }
}

impl<T> Drop for Future<T> {
    fn drop(&mut self) {
        if let FutureState::Demand(wakers) = self.state().deref_mut() {
            // If the future is dropped while there are still wakers waiting,
            // we should wake them up to avoid deadlock.
            for waker in wakers.drain(..) {
                waker.wake();
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::{sync::Arc, time::Duration};

    use futures::future::join_all;
    use tokio::{sync::Notify, time::timeout};

    use super::*;

    #[test]
    fn new() {
        let future = Future::new();
        assert_eq!(future.try_get().as_deref(), None);
        assert_eq!(future.set("Hello world"), None);
        assert_eq!(future.try_get().as_deref(), Some(&"Hello world"));

        let future = Future::with("Hello World");
        assert_eq!(future.try_get().as_deref(), Some(&"Hello World"));
        assert_eq!(future.set("Hi"), Some("Hello World"));
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
                    assert!(matches!(future.poll_get(cx), Poll::Pending));
                    write.notify_one();

                    Poll::Ready(())
                })
                .await;

                assert_eq!(*future.get().await, "Hello world");
            }
        });

        write.notified().await;
        assert_eq!(future.set("Hello world"), None);

        task.await.unwrap();
    }

    #[tokio::test]
    async fn change() {
        let future = Arc::new(Future::<&str>::new());
        let write = Arc::new(Notify::new());
        let task = tokio::spawn({
            let future = future.clone();
            let write = write.clone();
            async move {
                core::future::poll_fn(|cx| {
                    assert!(matches!(future.poll_get(cx), Poll::Pending));
                    write.notify_one();
                    Poll::Ready(())
                })
                .await;

                assert_eq!(*future.get().await, "Hello world");
                assert_eq!(*future.get().await, "Hello world");
                write.notify_one();
            }
        });

        write.notified().await;
        assert_eq!(future.try_get().as_deref(), None);
        assert_eq!(future.set("Hello world"), None);
        write.notified().await;
        assert_eq!(future.set("Changed"), Some("Hello world"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn multiple_wait() {
        let future = Arc::new(Future::<&str>::new());
        let timeout_task = tokio::spawn({
            let future = future.clone();
            async move {
                let _ = timeout(Duration::from_millis(100), future.get()).await;
                let _ = future.set("Hello world");
            }
        });

        let task = tokio::spawn({
            let future = future.clone();
            async move {
                assert_eq!(*future.get().await, "Hello world");
            }
        });

        join_all([task, timeout_task]).await;
    }
}
