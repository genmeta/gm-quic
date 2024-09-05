use std::{
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

#[derive(Debug, Default, Clone)]
pub enum RawAsyncCell<T> {
    #[default]
    None,
    Demand(Waker),
    Ready(T),
    Invalid,
}

impl<T> RawAsyncCell<T> {
    /// Returns `true` if the async cell state is not [`Ready`] nor [`Invalid`].
    ///
    /// [`Ready`]: RawAsyncCell::Ready
    /// [`Invalid`]: RawAsyncCell::Invalid
    #[inline]
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::None | Self::Demand(..))
    }

    /// Returns `true` if the async cell state is [`Ready`].
    ///
    /// [`Ready`]: RawAsyncCell::Ready
    #[inline]
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(..))
    }

    /// Returns `true` if the async cell state is [`Invalid`].
    ///
    /// [`Invalid`]: RawAsyncCell::Invalid
    #[inline]
    #[must_use]
    pub fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid)
    }

    #[inline]
    pub fn write(&mut self, item: T) -> Result<Option<T>, T> {
        if let RawAsyncCell::Invalid = self {
            return Err(item);
        }
        if let RawAsyncCell::Demand(waker) = self {
            waker.wake_by_ref();
        }
        let previous = core::mem::replace(self, RawAsyncCell::Ready(item));
        match previous {
            RawAsyncCell::Ready(previous) => Ok(Some(previous)),
            _ => Ok(None),
        }
    }

    #[inline]
    pub fn take(&mut self) -> Option<T> {
        match std::mem::replace(self, RawAsyncCell::None) {
            RawAsyncCell::None => None,
            RawAsyncCell::Demand(waker) => {
                *self = RawAsyncCell::Demand(waker);
                None
            }
            RawAsyncCell::Invalid => {
                *self = RawAsyncCell::Invalid;
                None
            }
            RawAsyncCell::Ready(item) => Some(item),
        }
    }

    #[inline]
    pub fn poll_get(&mut self, cx: &mut Context<'_>) -> Poll<&mut Self> {
        match self {
            RawAsyncCell::None | RawAsyncCell::Demand(..) => {
                *self = RawAsyncCell::Demand(cx.waker().clone());
                Poll::Pending
            }
            RawAsyncCell::Ready(_) | RawAsyncCell::Invalid => Poll::Ready(self),
        }
    }

    #[inline]
    pub fn invalid(&mut self) {
        let previous = std::mem::replace(self, RawAsyncCell::Invalid);
        if let RawAsyncCell::Demand(waker) = previous {
            waker.wake();
        }
    }

    #[inline]
    pub fn as_ref(&self) -> Option<&T> {
        match self {
            RawAsyncCell::Ready(item) => Some(item),
            _ => None,
        }
    }

    #[inline]
    pub fn as_mut(&mut self) -> Option<&mut T> {
        match self {
            RawAsyncCell::Ready(item) => Some(item),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct AsyncCell<T> {
    state: Mutex<RawAsyncCell<T>>,
    // TODO: 本质上这是一个mpsc，是否需要某些机制强制保证只有一个consumer
    // 现在的实现，包括ConnError等，都是完全靠调用者保证的
}

impl<T> AsyncCell<T> {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn new_with(item: T) -> Self {
        Self {
            state: Mutex::new(RawAsyncCell::Ready(item)),
        }
    }

    #[inline]
    pub fn is_pending(&self) -> bool {
        self.state().is_pending()
    }

    #[inline]
    pub fn is_ready(&self) -> bool {
        self.state().is_ready()
    }

    #[inline]
    pub fn is_invalid(&self) -> bool {
        self.state().is_invalid()
    }

    #[inline]
    pub fn write(&self, item: T) -> Result<Option<T>, T> {
        self.state().write(item)
    }
    #[inline]
    pub fn take(&self) -> Option<T> {
        self.state().take()
    }

    /// Invalid the state
    ///
    /// return [`true`] if the state is invalided before this method is called
    #[inline]
    pub fn invalid(&self) {
        self.state().invalid();
    }

    #[inline]
    pub fn state(&self) -> MutexGuard<RawAsyncCell<T>> {
        self.state.lock().unwrap()
    }

    #[inline]
    pub fn poll_get(&self, cx: &mut Context<'_>) -> Poll<MutexGuard<'_, RawAsyncCell<T>>> {
        let mut guard = self.state();
        core::task::ready!(guard.poll_get(cx));
        Poll::Ready(guard)
    }

    #[inline]
    pub fn get<'a>(self: &'a Arc<Self>) -> Get<'a, T> {
        Get { cell: self }
    }
}

impl<T> Default for AsyncCell<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(RawAsyncCell::None),
        }
    }
}

pub struct Get<'s, T> {
    cell: &'s Arc<AsyncCell<T>>,
}

impl<T> Unpin for Get<'_, T> {}

impl<'s, T> Future for Get<'s, T> {
    type Output = MutexGuard<'s, RawAsyncCell<T>>;

    #[inline]
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.cell.poll_get(cx)
    }
}

#[cfg(test)]
mod tests {

    use tokio::sync::Notify;

    use super::*;

    #[test]
    fn new() {
        let cell = AsyncCell::new();
        assert!(cell.is_pending());
        assert_eq!(cell.state().as_ref(), None);
        assert_eq!(cell.state().as_mut(), None);

        assert_eq!(cell.write("Hello world"), Ok(None));
        assert!(cell.is_ready());
        assert!(cell.state().as_ref().is_some());
        *cell.state().as_mut().unwrap() = "Hello World";
        assert_eq!(cell.take(), Some("Hello World"));

        let cell = AsyncCell::new_with("Hello World");
        assert_eq!(cell.write("Hello world"), Ok(Some("Hello World")));
        assert_eq!(cell.take(), Some("Hello world"));
    }
    #[tokio::test]
    async fn wait() {
        let cell = Arc::new(AsyncCell::<&str>::new());
        let write = Arc::new(Notify::new());
        let task = tokio::spawn({
            let cell = cell.clone();
            let write = write.clone();
            async move {
                assert!(matches!(
                    core::future::poll_fn(|cx| Poll::Ready(cell.poll_get(cx))).await,
                    Poll::Pending
                ));

                write.notify_one();
                let raw_cell = cell.get().await;
                assert_eq!(raw_cell.as_ref(), Some(&"Hello world"));
            }
        });

        write.notified().await;
        assert!(cell.is_pending());
        assert_eq!(cell.write("Hello world"), Ok(None));

        task.await.unwrap();
    }

    #[tokio::test]
    async fn invalid() {
        let cell = Arc::new(AsyncCell::new());

        assert_eq!(cell.write("Hello world"), Ok(None));

        cell.invalid();
        assert!(cell.is_invalid());

        assert_eq!(cell.write("Hello world"), Err("Hello world"));
        assert_eq!(cell.take(), None);

        let poll = core::future::poll_fn(|cx| Poll::Ready(cell.poll_get(cx))).await;
        let Poll::Ready(raw_cell) = poll else {
            panic!()
        };
        assert!(raw_cell.is_invalid());
    }

    #[tokio::test]
    async fn wakeup_on_invalid() {
        let invalid = Arc::new(Notify::new());
        let cell = Arc::new(AsyncCell::<&str>::new());
        let task = tokio::spawn({
            let cell = cell.clone();
            let invalid = invalid.clone();
            async move {
                assert!(matches!(
                    core::future::poll_fn(|cx| Poll::Ready(cell.poll_get(cx))).await,
                    Poll::Pending
                ));
                invalid.notify_one();
                assert_eq!(cell.get().await.take(), None);
            }
        });

        invalid.notified().await;
        cell.invalid();
        task.await.unwrap();
    }

    #[test]
    fn put_after_invalid() {
        let cell = Arc::new(AsyncCell::new());
        assert_eq!(cell.take(), None);
        cell.invalid();
        assert_eq!(cell.write("Hello world"), Err("Hello world"));
        assert_eq!(cell.take(), None);
    }
}
