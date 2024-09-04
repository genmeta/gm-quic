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
    /// Returns `true` if the async cell state is [`None`].
    ///
    /// [`None`]: AsyncCellState::None
    #[must_use]
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns `true` if the async cell state is [`Demand`].
    ///
    /// [`Demand`]: AsyncCellState::Demand
    #[must_use]
    pub fn is_demand(&self) -> bool {
        matches!(self, Self::Demand(..))
    }

    /// Returns `true` if the async cell state is [`Ready`].
    ///
    /// [`Ready`]: AsyncCellState::Ready
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(..))
    }

    /// Returns `true` if the async cell state is [`Invalid`].
    ///
    /// [`Invalid`]: AsyncCellState::Invalid
    #[must_use]
    pub fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid)
    }

    /// Replace the current value with a new one directly with out wakeup the consumer
    ///
    /// be different from [`AsyncCellState::write_option`], this method will not
    /// wake the consumer though the state is [`AsyncCellState::Demand`] and the new value is not [`None`]
    pub fn repace(&mut self, opt: Option<T>) -> Result<Option<T>, Option<T>> {
        if self.is_invalid() {
            return Err(opt);
        }
        let previous = self.take();
        if let Some(item) = opt {
            *self = RawAsyncCell::Ready(item);
        }
        Ok(previous)
    }

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

    pub fn wtite_if<F>(&mut self, item: T, predicate: F) -> Result<Option<T>, T>
    where
        F: FnOnce(&Option<T>) -> bool,
    {
        if let RawAsyncCell::Invalid = self {
            return Err(item);
        }

        let previous = self.take();
        if predicate(&previous) {
            let _write_result = self.write(item);
            debug_assert!(_write_result.is_ok());
            Ok(previous)
        } else {
            // the previosu value is not changed
            let _replace_result = self.repace(previous);
            debug_assert!(_replace_result.is_ok());
            Err(item)
        }
    }

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

    pub fn poll_wait(&mut self, cx: &mut Context<'_>) -> Poll<&mut Self> {
        match self {
            RawAsyncCell::None | RawAsyncCell::Demand(..) => {
                *self = RawAsyncCell::Demand(cx.waker().clone());
                Poll::Pending
            }
            RawAsyncCell::Ready(_) | RawAsyncCell::Invalid => Poll::Ready(self),
        }
    }

    pub fn invalid(&mut self) {
        let previous = std::mem::replace(self, RawAsyncCell::Invalid);
        if let RawAsyncCell::Demand(waker) = previous {
            waker.wake();
        }
    }

    pub fn as_ref(&self) -> Option<&T> {
        match self {
            RawAsyncCell::Ready(item) => Some(item),
            _ => None,
        }
    }

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
    pub fn is_none(&self) -> bool {
        self.state().is_none()
    }

    #[inline]
    pub fn is_demand(&self) -> bool {
        self.state().is_demand()
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
    pub fn write_if<F>(&self, item: T, predicate: F) -> Result<Option<T>, T>
    where
        F: FnOnce(&Option<T>) -> bool,
    {
        self.state().wtite_if(item, predicate)
    }

    #[inline]
    pub fn replace(&self, opt: Option<T>) -> Result<Option<T>, Option<T>> {
        self.state().repace(opt)
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

    pub fn poll_wait(&self, cx: &mut Context<'_>) -> Poll<MutexGuard<'_, RawAsyncCell<T>>> {
        let mut guard = self.state();
        core::task::ready!(guard.poll_wait(cx));
        Poll::Ready(guard)
    }

    pub fn wait<'a>(self: &'a Arc<Self>) -> Wait<'a, T> {
        Wait { cell: self }
    }
}

impl<T> Default for AsyncCell<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(RawAsyncCell::None),
        }
    }
}

pub struct Wait<'s, T> {
    cell: &'s Arc<AsyncCell<T>>,
}

impl<T> Unpin for Wait<'_, T> {}

impl<'s, T> Future for Wait<'s, T> {
    type Output = MutexGuard<'s, RawAsyncCell<T>>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.cell.poll_wait(cx)
    }
}

#[cfg(test)]
mod tests {

    use tokio::sync::Notify;

    use super::*;

    #[test]
    fn new() {
        let cell = AsyncCell::new();
        assert!(cell.is_none());
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
                    core::future::poll_fn(|cx| Poll::Ready(cell.poll_wait(cx))).await,
                    Poll::Pending
                ));

                write.notify_one();
                let raw_cell = cell.wait().await;
                assert_eq!(raw_cell.as_ref(), Some(&"Hello world"));
            }
        });

        write.notified().await;
        assert!(cell.is_demand());
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
        assert_eq!(cell.write_if("hw", Option::is_none), Err("hw"));
        assert_eq!(cell.replace(Some("hw")), Err(Some("hw")));
        assert_eq!(cell.take(), None);

        let poll = core::future::poll_fn(|cx| Poll::Ready(cell.poll_wait(cx))).await;
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
                    core::future::poll_fn(|cx| Poll::Ready(cell.poll_wait(cx))).await,
                    Poll::Pending
                ));
                invalid.notify_one();
                assert_eq!(cell.wait().await.take(), None);
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

    #[test]
    fn write_if() {
        let cell = Arc::new(AsyncCell::new());
        assert_eq!(cell.write_if("Hello World", Option::is_none), Ok(None));
        assert_eq!(
            cell.write_if("Hello world", |s| s.is_none()),
            Err("Hello world")
        );
        assert_eq!(
            cell.write_if("Hello world", |s| s.is_some()),
            Ok(Some("Hello World"))
        );
        assert_eq!(cell.take(), Some("Hello world"));
    }

    #[tokio::test]
    async fn replace() {
        let cell = AsyncCell::new();
        assert_eq!(cell.replace(Some("Hello world")), Ok(None));
        assert!(cell.is_ready());
    }
}
