use std::{
    future::Future,
    marker::PhantomData,
    ops::DerefMut,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

#[derive(Debug, Default, Clone)]
enum AsyncCellState<T> {
    #[default]
    None,
    Demand(Waker),
    Ready(T),
    Invalid,
}

impl<T> AsyncCellState<T> {
    fn modify<U, F>(&mut self, f: F) -> Option<U>
    where
        F: FnOnce(&mut Option<T>) -> U,
    {
        let (waker, mut opt) = match std::mem::replace(self, AsyncCellState::Invalid) {
            AsyncCellState::None => (None, None),
            AsyncCellState::Demand(waker) => (Some(waker), None),
            AsyncCellState::Ready(item) => (None, Some(item)),
            AsyncCellState::Invalid => return None,
        };
        let r = f(&mut opt);

        *self = match (waker, opt) {
            (None, None) => AsyncCellState::None,
            (None, Some(item)) => AsyncCellState::Ready(item),
            (Some(waker), None) => AsyncCellState::Demand(waker),
            (Some(waker), Some(item)) => {
                waker.wake();
                AsyncCellState::Ready(item)
            }
        };

        Some(r)
    }
}

#[derive(Debug)]
struct RawAsyncCell<T> {
    state: Mutex<AsyncCellState<T>>,
    // TODO: 本质上这是一个mpsc，是否需要某些机制强制保证只有一个consumer
    // 现在的实现，包括ConnError等，都是完全靠调用者保证的
}

impl<T> Default for RawAsyncCell<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(AsyncCellState::None),
        }
    }
}

#[derive(Debug)]
pub struct AsyncCell<T> {
    raw: Arc<RawAsyncCell<T>>,
}

impl<T> Clone for AsyncCell<T> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
        }
    }
}

impl<T> Default for AsyncCell<T> {
    fn default() -> Self {
        Self {
            raw: Arc::new(Default::default()),
        }
    }
}

impl<T> AsyncCell<T> {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn new_with(item: T) -> Self {
        Self {
            raw: Arc::new(RawAsyncCell {
                state: Mutex::new(AsyncCellState::Ready(item)),
            }),
        }
    }

    pub fn write(&self, item: T) -> Result<Option<T>, T> {
        let mut state = self.raw.state.lock().unwrap();
        let state = state.deref_mut();

        if let AsyncCellState::Invalid = state {
            return Err(item);
        }
        if let AsyncCellState::Demand(waker) = state {
            waker.wake_by_ref();
        }
        let previous = core::mem::replace(state, AsyncCellState::Ready(item));
        match previous {
            AsyncCellState::Ready(previous) => Ok(Some(previous)),
            _ => Ok(None),
        }
    }

    #[inline]
    pub fn write_if<F>(&self, item: T, predicate: F) -> Result<Option<T>, T>
    where
        F: FnOnce(&Option<T>) -> bool,
    {
        let mut state = self.raw.state.lock().unwrap();
        let state = state.deref_mut();

        if let AsyncCellState::Invalid = state {
            return Err(item);
        }

        state
            .modify(|opt| {
                if predicate(opt) {
                    Ok(opt.replace(item))
                } else {
                    Err(item)
                }
            })
            .unwrap()
    }

    #[inline]
    pub fn take(&self) -> Option<T> {
        let mut state = self.raw.state.lock().unwrap();
        let state = state.deref_mut();
        match std::mem::replace(state, AsyncCellState::None) {
            AsyncCellState::None | AsyncCellState::Demand(_) => None,
            AsyncCellState::Invalid => {
                *state = AsyncCellState::Invalid;
                None
            }
            AsyncCellState::Ready(item) => Some(item),
        }
    }

    #[inline]
    pub fn poll_take_out(&self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut state = self.raw.state.lock().unwrap();
        let state = state.deref_mut();
        match std::mem::replace(state, AsyncCellState::None) {
            AsyncCellState::None | AsyncCellState::Demand(_) => {
                *state = AsyncCellState::Demand(cx.waker().clone());
                Poll::Pending
            }
            AsyncCellState::Invalid => {
                *state = AsyncCellState::Invalid;
                Poll::Ready(None)
            }
            AsyncCellState::Ready(item) => Poll::Ready(Some(item)),
        }
    }

    #[inline]
    pub fn poll_take_clone(&self, cx: &mut Context<'_>) -> Poll<Option<T>>
    where
        T: Clone,
    {
        let mut state = self.raw.state.lock().unwrap();
        let state = state.deref_mut();
        match state {
            AsyncCellState::None | AsyncCellState::Demand(_) => {
                *state = AsyncCellState::Demand(cx.waker().clone());
                Poll::Pending
            }
            AsyncCellState::Invalid => Poll::Ready(None),
            AsyncCellState::Ready(item) => Poll::Ready(Some(item.clone())),
        }
    }

    #[inline]
    pub fn invalid(&self) {
        let mut state = self.raw.state.lock().unwrap();
        let state = state.deref_mut();
        if let AsyncCellState::Demand(waker) = state {
            waker.wake_by_ref();
        }
        *state = AsyncCellState::Invalid;
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

    #[inline]
    pub fn modify<U, F>(&self, f: F) -> Option<U>
    where
        F: FnOnce(&mut Option<T>) -> U,
    {
        self.raw.state.lock().unwrap().modify(f)
    }
}

pub struct TakeOut<'s, T> {
    cell: &'s AsyncCell<T>,
}

impl<T: Unpin> Unpin for TakeOut<'_, T> {}

impl<T> Future for TakeOut<'_, T> {
    type Output = Option<T>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.cell.poll_take_out(cx)
    }
}

pub struct TakeClone<'s, T> {
    cell: &'s AsyncCell<T>,
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
    cell: &'s AsyncCell<T>,
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
        let cell = AsyncCell::new();
        assert_eq!(cell.write("Hello world"), Ok(None));
        assert_eq!(cell.take(), Some("Hello world"));

        let cell = AsyncCell::new_with("Hello World");
        assert_eq!(cell.write("Hello world"), Ok(Some("Hello World")));
        assert_eq!(cell.take(), Some("Hello world"));
    }

    #[tokio::test]
    async fn take_out() {
        let cell = AsyncCell::new();
        assert_eq!(cell.write("Hello world"), Ok(None));
        assert_eq!(cell.take_out().await, Some("Hello world"));

        let putin = Arc::new(Notify::new());
        let cell = AsyncCell::new();
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
        let cell = AsyncCell::new();
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
        let cell: AsyncCell<&str> = AsyncCell::new();
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
        let cell: AsyncCell<&str> = AsyncCell::new();

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
        let cell: AsyncCell<&str> = AsyncCell::new();
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
        let cell: AsyncCell<&str> = AsyncCell::new();
        assert_eq!(cell.take(), None);
        cell.invalid();
        assert_eq!(cell.write("Hello world"), Err("Hello world"));
        assert_eq!(cell.take(), None);
    }

    #[test]
    fn modify() {
        let cell: AsyncCell<&str> = AsyncCell::new();
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
        let cell: AsyncCell<&str> = AsyncCell::new();
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
        let cell: AsyncCell<&str> = AsyncCell::new();
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
