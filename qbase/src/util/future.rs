use std::{
    ops::Deref,
    sync::{Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

#[derive(Debug, Default, Clone)]
pub(crate) enum FutureState<T> {
    #[default]
    None,
    Demand(Waker),
    Ready(T),
}

/// A value which will be resolved in the future.
///
/// Be different with the [`futures::Future`], this is a value not a computation.
///
/// The [`Future`] can only been assigned once, and the value can be get multiple times.(so the T
/// must be [`Clone`]). If the assign is called multiple times, the old value will not be replaced,
/// and the new value will be returned as [`Err`].
///
/// The task can attempt to get the value synchronously by calling [`try_get`], or asynchronously by
/// calling [`get`]. There are also a [`poll_get`] method for the task to poll the value. Read their
/// document for more details about the behavior.
///
/// # Examples
/// ``` rust, no_run
/// # async fn some_work() -> &'static str { "Hello World" }
/// # async fn test() {
/// use qbase::util::Future;
/// use std::sync::Arc;
///
/// let fut = Arc::new(Future::new());
/// let t1 = tokio::spawn({
///     let fut = fut.clone();
///     async move {
///         assert_eq!(fut.get().await, "Hello world");
///         // the value can be get multiple times
///         assert_eq!(fut.get().await, "Hello world");
///         assert_eq!(fut.get().await, "Hello world");
///     }
/// });
///
/// let t2 = tokio::spawn({
///     let fut = fut.clone();
///     async move {
///         // do some work to get the value
///         let value = some_work().await;
///         fut.assign(value);
///
///         // the new value will not replace the old value
///         assert_eq!(fut.assign("Hi World"), Err("Hi World"));
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

impl<T: Clone> Future<T> {
    /// Create a new empty [`Future`].
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a new [`Future`] with the given value in it.
    ///
    /// Once that the future can only been assigned once, its not a good idea to use this method,
    /// why dont you use the value directly or share the value with the [`Arc`]?
    ///
    /// [`Arc`]: std::sync::Arc
    #[inline]
    pub fn with(item: T) -> Self {
        Self {
            state: Mutex::new(FutureState::Ready(item)),
        }
    }

    pub(crate) fn state(&self) -> MutexGuard<FutureState<T>> {
        self.state.lock().unwrap()
    }

    /// Assign the value to the [`Future`].
    ///
    /// If its the first time to assign the value, [`Ok`] will be returned.
    ///
    /// If the value has been assigned before, the new value will not replace the old value, and
    /// the new value will be returned as [`Err`].
    #[inline]
    pub fn assign(&self, item: T) -> Result<(), T> {
        let mut state = self.state();
        match state.deref() {
            FutureState::None => {}
            FutureState::Demand(waker) => waker.wake_by_ref(),
            FutureState::Ready(_) => return Err(item),
        }
        *state = FutureState::Ready(item);
        Ok(())
    }

    /// Poll the value of the [`Future`].
    ///
    /// If the value is ready, the value will be returned as [`Poll::Ready`]. If the value is not
    /// ready, this method will return [`Poll::Pending`] and the waker will be stored.
    ///
    /// Note that if there has been a waker stored(there has been a task waiting for the value), and
    /// the new waker is different from the old waker(tested by [`Waker::will_wake`]), the method will
    /// panic.
    ///
    /// This case is usually caused by the value being waited by multiple tasks, which is not allowed.
    ///
    /// # Cancel Safe
    ///
    /// If you use this method directly, the future is not cancel safe, when the task is dropped, the
    /// waker will **not** be dropped. When the method called next time, the method may panic because
    /// there has been a waker stored(a canceled task).
    ///
    /// If you want to make the future cancel safe, you should use the [`Get`] instead of this method.
    #[inline]
    pub fn poll_get(&self, cx: &mut Context<'_>) -> Poll<T> {
        let mut raw_future = self.state();
        match raw_future.deref() {
            FutureState::None => {
                *raw_future = FutureState::Demand(cx.waker().clone());
                Poll::Pending
            }
            FutureState::Ready(item) => Poll::Ready(item.clone()),
            FutureState::Demand(waker) => {
                if !waker.will_wake(cx.waker()) {
                    drop(raw_future);
                    panic!("trying to wait on a future from multiple tasks");
                }
                Poll::Pending
            }
        }
    }

    /// Try to get the value of the [`Future`].
    ///
    /// If the value is ready, the value will be returned as [`Some`]. If the value is not ready, this
    /// method will return [`None`].
    pub fn try_get(&self) -> Option<T> {
        match self.state().deref() {
            FutureState::Ready(item) => Some(item.clone()),
            _ => None,
        }
    }

    /// Get the value of the [`Future`] asynchronously.
    ///
    /// ``` rust, ignore
    /// async fn get(&self) -> T
    /// ```
    ///
    /// The method will return a [`Get`] future, which will poll the value of the [`Future`] when
    /// the task is polled.
    ///
    /// Note that there can only be one task waiting for the value, if there are multiple tasks
    /// waiting for the value, the method will panic.
    ///
    /// # Cancel Safe
    ///
    /// The [`Get`] future is cancel safe, when the task is dropped, the waker will be dropped too,
    /// a new task can wait for the value again.
    #[inline]
    pub fn get(&self) -> Get<'_, T> {
        Get(self)
    }
}

impl<T> Default for Future<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(FutureState::None),
        }
    }
}

/// A future which will poll the value of the [`Future`] asynchronously.
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
        if let FutureState::Demand(waker) = raw_future.deref() {
            // If the Value dropped because the task is dropped, wake is noop.
            // If the Value dropped bacause panic(racing), this is wake up another task.
            waker.wake_by_ref();
            *raw_future = FutureState::None;
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
                    *future.state() = FutureState::None;

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
        };
    }
}
