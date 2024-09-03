use std::{
    future::Future,
    marker::PhantomData,
    ops::DerefMut,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use deref_derive::Deref;

#[derive(Debug, Default, Clone)]
pub enum AsyncCellState<T> {
    #[default]
    None,
    Demand(Waker),
    Ready(T),
    Invalid,
}

impl<T> AsyncCellState<T> {
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
        *self = AsyncCellState::Ready(item);
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
            *self = AsyncCellState::Ready(item);
        }
        Ok(previous)
    }

    pub fn write(&mut self, item: T) -> Result<Option<T>, T> {
        if let AsyncCellState::Invalid = self {
            return Err(item);
        }
        if let AsyncCellState::Demand(waker) = self {
            waker.wake_by_ref();
        }
        let previous = core::mem::replace(self, AsyncCellState::Ready(item));
        match previous {
            AsyncCellState::Ready(previous) => Ok(Some(previous)),
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
            (AsyncCellState::Invalid, item) => Err(item),
            (previous, None) => {
                *self = previous;
                Ok(None)
            }
            (AsyncCellState::None, Some(item)) => {
                *self = AsyncCellState::Ready(item);
                Ok(None)
            }
            (AsyncCellState::Demand(waker), Some(item)) => {
                waker.wake();
                *self = AsyncCellState::Ready(item);
                Ok(None)
            }
            (AsyncCellState::Ready(previous), Some(new)) => {
                *self = AsyncCellState::Ready(new);
                Ok(Some(previous))
            }
        }
    }

    pub fn wtite_if<F>(&mut self, item: T, predicate: F) -> Result<Option<T>, T>
    where
        F: FnOnce(&Option<T>) -> bool,
    {
        if let AsyncCellState::Invalid = self {
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
        match std::mem::replace(self, AsyncCellState::None) {
            AsyncCellState::None => None,
            AsyncCellState::Demand(waker) => {
                *self = AsyncCellState::Demand(waker);
                None
            }
            AsyncCellState::Invalid => {
                *self = AsyncCellState::Invalid;
                None
            }
            AsyncCellState::Ready(item) => Some(item),
        }
    }

    pub fn poll_take_out(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        match std::mem::replace(self, AsyncCellState::None) {
            AsyncCellState::None | AsyncCellState::Demand(_) => {
                *self = AsyncCellState::Demand(cx.waker().clone());
                Poll::Pending
            }
            AsyncCellState::Invalid => {
                *self = AsyncCellState::Invalid;
                Poll::Ready(None)
            }
            AsyncCellState::Ready(item) => Poll::Ready(Some(item)),
        }
    }

    pub fn poll_take_clone(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>>
    where
        T: Clone,
    {
        match self {
            AsyncCellState::None | AsyncCellState::Demand(_) => {
                *self = AsyncCellState::Demand(cx.waker().clone());
                Poll::Pending
            }
            AsyncCellState::Ready(item) => Poll::Ready(Some(item.clone())),
            AsyncCellState::Invalid => Poll::Ready(None),
        }
    }

    pub fn invalid(&mut self) {
        let previous = std::mem::replace(self, AsyncCellState::Invalid);
        if let AsyncCellState::Demand(waker) = previous {
            waker.wake();
        }
    }

    pub fn as_ref(&self) -> Option<&T> {
        match self {
            AsyncCellState::Ready(item) => Some(item),
            _ => None,
        }
    }

    pub fn as_mut(&mut self) -> Option<&mut T> {
        match self {
            AsyncCellState::Ready(item) => Some(item),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct AsyncCell<T> {
    state: Mutex<AsyncCellState<T>>,
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
            state: Mutex::new(AsyncCellState::Ready(item)),
        }
    }

    #[inline]
    pub fn is_none(&self) -> bool {
        self.state.lock().unwrap().is_none()
    }

    #[inline]
    pub fn is_demand(&self) -> bool {
        self.state.lock().unwrap().is_demand()
    }

    #[inline]
    pub fn is_ready(&self) -> bool {
        self.state.lock().unwrap().is_ready()
    }

    #[inline]
    pub fn is_invalid(&self) -> bool {
        self.state.lock().unwrap().is_invalid()
    }

    #[inline]
    pub fn write(&self, item: T) -> Result<Option<T>, T> {
        self.state.lock().unwrap().write(item)
    }

    #[inline]
    pub fn write_if<F>(&self, item: T, predicate: F) -> Result<Option<T>, T>
    where
        F: FnOnce(&Option<T>) -> bool,
    {
        self.state.lock().unwrap().wtite_if(item, predicate)
    }

    #[inline]
    pub fn take(&self) -> Option<T> {
        self.state.lock().unwrap().take()
    }

    #[inline]
    pub fn poll_take_out(&self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.state.lock().unwrap().poll_take_out(cx)
    }

    #[inline]
    pub fn poll_take_clone(&self, cx: &mut Context<'_>) -> Poll<Option<T>>
    where
        T: Clone,
    {
        self.state.lock().unwrap().poll_take_clone(cx)
    }

    /// Invalid the state
    ///
    /// return [`true`] if the state is invalided before this method is called
    #[inline]
    pub fn invalid(&self) {
        self.state.lock().unwrap().invalid();
    }

    #[inline]
    pub fn modify<U, F>(&self, f: F) -> Option<U>
    where
        F: FnOnce(&mut Option<T>) -> U,
    {
        self.state.lock().unwrap().modify(f)
    }

    #[inline]
    pub fn replace(&self, opt: Option<T>) -> Result<Option<T>, Option<T>> {
        self.state.lock().unwrap().write_option(opt)
    }

    #[inline]
    pub fn state(&self) -> MutexGuard<AsyncCellState<T>> {
        self.state.lock().unwrap()
    }
}

impl<T> Default for AsyncCell<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(AsyncCellState::None),
        }
    }
}

#[derive(Debug, Deref)]
pub struct ArcAsyncCell<T> {
    raw: Arc<AsyncCell<T>>,
}

impl<T> Clone for ArcAsyncCell<T> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
        }
    }
}

impl<T> Default for ArcAsyncCell<T> {
    fn default() -> Self {
        Self {
            raw: Arc::new(Default::default()),
        }
    }
}

impl<T> From<Arc<AsyncCell<T>>> for ArcAsyncCell<T> {
    fn from(raw: Arc<AsyncCell<T>>) -> Self {
        Self { raw }
    }
}

impl<T> From<AsyncCell<T>> for ArcAsyncCell<T> {
    fn from(raw: AsyncCell<T>) -> Self {
        Arc::new(raw).into()
    }
}

impl<T> ArcAsyncCell<T> {
    #[inline]
    pub fn new() -> Self {
        Self {
            raw: Arc::new(AsyncCell::new()),
        }
    }

    #[inline]
    pub fn new_with(item: T) -> Self {
        Self {
            raw: Arc::new(AsyncCell::new_with(item)),
        }
    }

    #[inline]
    pub fn take_out(&self) -> TakeOut<'_, T> {
        TakeOut { cell: self }
    }

    #[inline]
    pub fn take_clone(&self) -> TakeClone<'_, T> {
        TakeClone { cell: self }
    }

    // 由于Mutex::map不稳定，暂时无法通过任何方法实现返回一个&mut T, 此方法为一个替代方案
    #[inline]
    pub fn compute<U, F>(&self, operator: F) -> Compute<'_, T, U, F>
    where
        F: FnOnce(&mut T) -> U + Unpin,
    {
        Compute {
            cell: self,
            operator: Some(operator),
            _phantom: PhantomData,
        }
    }
}

pub struct TakeOut<'s, T> {
    cell: &'s ArcAsyncCell<T>,
}

impl<T: Unpin> Unpin for TakeOut<'_, T> {}

impl<T> Future for TakeOut<'_, T> {
    type Output = Option<T>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.cell.poll_take_out(cx)
    }
}

pub struct TakeClone<'s, T> {
    cell: &'s ArcAsyncCell<T>,
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

pub struct Compute<'s, T, U, F> {
    cell: &'s ArcAsyncCell<T>,
    operator: Option<F>,
    _phantom: PhantomData<U>,
}

impl<T, U, F: Unpin> Unpin for Compute<'_, T, U, F> {}

impl<T, U, F> Future for Compute<'_, T, U, F>
where
    F: FnOnce(&mut T) -> U + Unpin,
{
    type Output = Option<U>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut state = this.cell.raw.state.lock().unwrap();
        let state = state.deref_mut();
        match state {
            AsyncCellState::None | AsyncCellState::Demand(_) => {
                *state = AsyncCellState::Demand(cx.waker().clone());
                Poll::Pending
            }
            AsyncCellState::Ready(item) => {
                let operator = this.operator.take().expect("the future has yeilded");
                Poll::Ready(Some(operator(item)))
            }
            AsyncCellState::Invalid => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::future::pending;

    use tokio::sync::Notify;

    use super::*;

    #[test]
    fn new() {
        let cell = ArcAsyncCell::new();
        assert_eq!(cell.write("Hello world"), Ok(None));
        assert_eq!(cell.take(), Some("Hello world"));

        let cell = ArcAsyncCell::new_with("Hello World");
        assert_eq!(cell.write("Hello world"), Ok(Some("Hello World")));
        assert_eq!(cell.take(), Some("Hello world"));

        let cell = AsyncCell::<()>::new();
        let _arc_cell = ArcAsyncCell::from(cell);

        let cell = AsyncCell::<()>::new();
        let _arc_cell = ArcAsyncCell::from(Arc::new(cell));
    }

    #[tokio::test]
    async fn take_out() {
        let cell = ArcAsyncCell::new();
        assert_eq!(cell.write("Hello world"), Ok(None));
        assert_eq!(cell.take_out().await, Some("Hello world"));

        let putin = Arc::new(Notify::new());
        let cell = ArcAsyncCell::new();
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
        assert_eq!(cell.write("Hello world"), Ok(None));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn take_clone() {
        let putin = Arc::new(Notify::new());
        let cell = ArcAsyncCell::new();
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
    async fn compute() {
        let putin = Arc::new(Notify::new());
        let cell: ArcAsyncCell<&str> = ArcAsyncCell::new();
        let task = tokio::spawn({
            let cell = cell.clone();
            let putin = putin.clone();
            async move {
                assert!(matches!(
                    core::future::poll_fn(|cx| Poll::Ready(cell.poll_take_out(cx))).await,
                    Poll::Pending
                ));
                putin.notify_one();
                assert_eq!(cell.compute(|s| s.len()).await, Some(11));
                assert_eq!(cell.compute(|s| s.len()).await, Some(11));
                assert_eq!(cell.compute(|s| s.len()).await, Some(11));
            }
        });

        putin.notified().await;
        assert_eq!(cell.write("Hello world"), Ok(None));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn invalid() {
        let cell: ArcAsyncCell<&str> = ArcAsyncCell::new();

        assert_eq!(cell.write("Hello world"), Ok(None));
        assert_eq!(cell.take_out().await, Some("Hello world"));

        cell.invalid();
        assert_eq!(cell.take_out().await, None);
        assert_eq!(cell.take_clone().await, None);
        assert_eq!(cell.compute(|s| s.len()).await, None);
        assert_eq!(cell.take(), None);
    }

    #[tokio::test]
    async fn wakeup_on_invalid() {
        let invalid = Arc::new(Notify::new());
        let cell: ArcAsyncCell<&str> = ArcAsyncCell::new();
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
        let cell: ArcAsyncCell<&str> = ArcAsyncCell::new();
        assert_eq!(cell.take(), None);
        cell.invalid();
        assert_eq!(cell.write("Hello world"), Err("Hello world"));
        assert_eq!(cell.take(), None);
    }

    #[test]
    fn modify() {
        let cell: ArcAsyncCell<&str> = ArcAsyncCell::new();
        assert_eq!(cell.modify(|s| s.map(|s| s.len())), Some(None));
        assert_eq!(cell.write("Hello world"), Ok(None));
        assert_eq!(cell.modify(|s| s.take().map(|s| s.len())), Some(Some(11)));
        assert_eq!(cell.take(), None);
        assert_eq!(cell.modify(|s| s.map(|s| s.len())), Some(None));
        cell.invalid();
        assert_eq!(cell.modify(|s| s.take().map(|s| s.len())), None);
    }

    #[tokio::test]
    async fn wake_by_modify() {
        let putin = Arc::new(Notify::new());
        let cell: ArcAsyncCell<&str> = ArcAsyncCell::new();
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
    fn put_if() {
        let cell: ArcAsyncCell<&str> = ArcAsyncCell::new();
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
}
