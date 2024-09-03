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

    pub fn replace(&mut self, item: T) -> Result<Option<T>, T> {
        if self.is_invalid() {
            return Err(item);
        }
        let previous = self.take();
        *self = RawAsyncCell::Ready(item);
        Ok(previous)
    }

    /// Replace the current value with a new one directly with out wakeup the consumer
    ///
    /// be different from [`AsyncCellState::write_option`], this method will not
    /// wake the consumer though the state is [`AsyncCellState::Demand`] and the new value is not [`None`]
    pub fn replace_option(&mut self, opt: Option<T>) -> Result<Option<T>, Option<T>> {
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

    /// Write a new value to the async cell state
    ///
    /// * if the cell is [`AsyncCellState::Invalid`], the new value will be returned as [`Err`]
    /// * if there has been a value in the cell, the new value will be returned as [`Ok(Some(T))`],
    /// * if there is no value in the cell, the new value will be returned as [`Ok(None)`]
    /// * if the cell is [`AsyncCellState::Demand`], the waker will be waked
    pub fn write_option(&mut self, opt: Option<T>) -> Result<Option<T>, Option<T>> {
        match (std::mem::replace(self, Self::Invalid), opt) {
            (RawAsyncCell::Invalid, item) => Err(item),
            (RawAsyncCell::Ready(previous), None) => {
                *self = RawAsyncCell::None;
                Ok(Some(previous))
            }
            (previous, None) => {
                *self = previous;
                Ok(None)
            }
            (RawAsyncCell::None, Some(item)) => {
                *self = RawAsyncCell::Ready(item);
                Ok(None)
            }
            (RawAsyncCell::Demand(waker), Some(item)) => {
                waker.wake();
                *self = RawAsyncCell::Ready(item);
                Ok(None)
            }
            (RawAsyncCell::Ready(previous), Some(new)) => {
                *self = RawAsyncCell::Ready(new);
                Ok(Some(previous))
            }
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
            let _replace_result = self.replace_option(previous);
            debug_assert!(_replace_result.is_ok());
            Err(item)
        }
    }

    pub fn modify<U, F>(&mut self, f: F) -> Option<U>
    where
        F: FnOnce(&mut Option<T>) -> U,
    {
        if self.is_invalid() {
            return None;
        }

        let mut opt = self.take();
        let result = f(&mut opt);
        // the previous value may be changed
        let _replace_result = self.write_option(opt);
        debug_assert!(_replace_result.is_ok());

        Some(result)
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

    pub fn poll_take_out(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        match std::mem::replace(self, RawAsyncCell::None) {
            RawAsyncCell::None | RawAsyncCell::Demand(_) => {
                *self = RawAsyncCell::Demand(cx.waker().clone());
                Poll::Pending
            }
            RawAsyncCell::Invalid => {
                *self = RawAsyncCell::Invalid;
                Poll::Ready(None)
            }
            RawAsyncCell::Ready(item) => Poll::Ready(Some(item)),
        }
    }

    pub fn poll_take_clone(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>>
    where
        T: Clone,
    {
        match self {
            RawAsyncCell::None | RawAsyncCell::Demand(_) => {
                *self = RawAsyncCell::Demand(cx.waker().clone());
                Poll::Pending
            }
            RawAsyncCell::Ready(item) => Poll::Ready(Some(item.clone())),
            RawAsyncCell::Invalid => Poll::Ready(None),
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
    pub fn write_option(&self, opt: Option<T>) -> Result<Option<T>, Option<T>> {
        self.state().write_option(opt)
    }

    #[inline]
    pub fn replace(&self, opt: T) -> Result<Option<T>, T> {
        self.state().replace(opt)
    }

    #[inline]
    pub fn replace_option(&self, opt: Option<T>) -> Result<Option<T>, Option<T>> {
        self.state().replace_option(opt)
    }

    #[inline]
    pub fn take(&self) -> Option<T> {
        self.state().take()
    }

    #[inline]
    pub fn poll_take_out(&self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.state().poll_take_out(cx)
    }

    #[inline]
    pub fn poll_take_clone(&self, cx: &mut Context<'_>) -> Poll<Option<T>>
    where
        T: Clone,
    {
        self.state().poll_take_clone(cx)
    }

    /// Invalid the state
    ///
    /// return [`true`] if the state is invalided before this method is called
    #[inline]
    pub fn invalid(&self) {
        self.state().invalid();
    }

    #[inline]
    pub fn modify<U, F>(&self, f: F) -> Option<U>
    where
        F: FnOnce(&mut Option<T>) -> U,
    {
        self.state().modify(f)
    }

    #[inline]
    pub fn state(&self) -> MutexGuard<RawAsyncCell<T>> {
        self.state.lock().unwrap()
    }

    #[inline]
    pub fn take_out<'a>(self: &'a Arc<Self>) -> TakeOut<'a, T> {
        TakeOut { cell: self }
    }

    #[inline]
    pub fn take_clone<'a>(self: &'a Arc<Self>) -> TakeClone<'a, T>
    where
        T: Clone,
    {
        TakeClone { cell: self }
    }
}

impl<T> Default for AsyncCell<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(RawAsyncCell::None),
        }
    }
}

pub struct TakeOut<'s, T> {
    cell: &'s Arc<AsyncCell<T>>,
}

impl<T: Unpin> Unpin for TakeOut<'_, T> {}

impl<T> Future for TakeOut<'_, T> {
    type Output = Option<T>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.cell.poll_take_out(cx)
    }
}

pub struct TakeClone<'s, T> {
    cell: &'s Arc<AsyncCell<T>>,
}

impl<T: Unpin> Unpin for TakeClone<'_, T> {}

impl<T> Future for TakeClone<'_, T>
where
    T: Clone,
{
    type Output = Option<T>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.cell.poll_take_clone(cx)
    }
}

#[cfg(test)]
mod tests {

    use std::future::pending;

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
    async fn take_out() {
        let cell = Arc::new(AsyncCell::new());
        assert_eq!(cell.write("Hello world"), Ok(None));
        assert_eq!(cell.take_out().await, Some("Hello world"));

        let putin = Arc::new(Notify::new());
        let cell = Arc::new(AsyncCell::new());
        let task = tokio::spawn({
            let cell = cell.clone();
            let putin = putin.clone();
            async move {
                assert!(matches!(
                    core::future::poll_fn(|cx| Poll::Ready(cell.poll_take_out(cx))).await,
                    Poll::Pending
                ));
                putin.notify_one();
                assert_eq!(cell.take_out().await, Some("Hello world"));
            }
        });

        putin.notified().await;
        assert!(cell.is_demand());
        assert_eq!(cell.write("Hello world"), Ok(None));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn take_clone() {
        let putin = Arc::new(Notify::new());
        let cell = Arc::new(AsyncCell::new());
        let task = tokio::spawn({
            let cell = cell.clone();
            let putin = putin.clone();
            async move {
                assert!(matches!(
                    core::future::poll_fn(|cx| Poll::Ready(cell.poll_take_clone(cx))).await,
                    Poll::Pending
                ));
                putin.notify_one();
                assert_eq!(cell.take_clone().await, Some("Hello world"));
                assert_eq!(cell.take_clone().await, Some("Hello world"));
                assert_eq!(cell.take_clone().await, Some("Hello world"));
            }
        });

        putin.notified().await;
        assert_eq!(cell.write("Hello world"), Ok(None));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn invalid() {
        let cell = Arc::new(AsyncCell::new());

        assert_eq!(cell.write("Hello world"), Ok(None));
        assert_eq!(cell.take_out().await, Some("Hello world"));

        cell.invalid();
        assert!(cell.is_invalid());
        assert_eq!(cell.take_out().await, None);
        assert_eq!(cell.take_clone().await, None);
        assert_eq!(cell.write("Hello world"), Err("Hello world"));
        assert_eq!(cell.write_option(Some("hw")), Err(Some("hw")));
        assert_eq!(cell.write_if("hw", Option::is_none), Err("hw"));
        assert_eq!(cell.replace("Hello world"), Err("Hello world"));
        assert_eq!(cell.replace_option(Some("hw")), Err(Some("hw")));
        assert_eq!(cell.modify(|s| s.take()), None);
        assert_eq!(cell.take(), None);
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
                    core::future::poll_fn(|cx| Poll::Ready(cell.poll_take_out(cx))).await,
                    Poll::Pending
                ));
                invalid.notify_one();
                assert_eq!(cell.take_out().await, None);
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
    fn modify() {
        let cell = Arc::new(AsyncCell::<&str>::new());
        assert_eq!(cell.modify(|s| s.map(|s| s.len())), Some(None));
        assert_eq!(cell.write("Hello world"), Ok(None));
        assert_eq!(cell.modify(|s| s.take().map(|s| s.len())), Some(Some(11)));
        assert_eq!(cell.take(), None);
        assert_eq!(cell.modify(|s| s.map(|s| s.len())), Some(None));
    }

    #[tokio::test]
    async fn wake_by_modify() {
        let putin = Arc::new(Notify::new());
        let cell = Arc::new(AsyncCell::<&str>::new());
        let task = tokio::spawn({
            let cell = cell.clone();
            let putin = putin.clone();
            async move {
                tokio::select! {
                    biased;
                    _ = cell.take_out() => {}
                    _ = {putin.notify_one();pending()} => {}
                }
            }
        });

        putin.notified().await;

        cell.modify(|s| *s = None);
        cell.modify(|s| *s = Some("Hello world"));

        task.await.unwrap();
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

    #[test]
    fn write_option() {
        let cell = Arc::new(AsyncCell::new());
        assert_eq!(cell.write_option(Some("Hello World")), Ok(None));
        assert_eq!(
            cell.write_option(Some("Hello world")),
            Ok(Some("Hello World"))
        );
        assert_eq!(cell.write_option(None), Ok(Some("Hello world")));
        assert_eq!(cell.take(), None);
    }
}
