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
    pub fn new() -> Self {
        Default::default()
    }

    pub fn new_with(item: T) -> Self {
        Self {
            raw: Arc::new(RawAsyncCell {
                state: Mutex::new(AsyncCellState::Ready(item)),
            }),
        }
    }

    pub fn put(&self, item: T) {
        let mut state = self.raw.state.lock().unwrap();
        let state = state.deref_mut();
        if let AsyncCellState::Invalid = state {
            return;
        }
        if let AsyncCellState::Demand(waker) = state {
            waker.wake_by_ref();
        }
        *state = AsyncCellState::Ready(item);
    }

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

    pub fn invalid(&self) {
        let mut state = self.raw.state.lock().unwrap();
        let state = state.deref_mut();
        if let AsyncCellState::Demand(waker) = state {
            waker.wake_by_ref();
        }
        *state = AsyncCellState::Invalid;
    }

    pub fn take_out(&self) -> TakeOut<'_, T> {
        TakeOut { cell: self }
    }

    pub fn take_clone(&self) -> TakeClone<'_, T> {
        TakeClone { cell: self }
    }

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

    use tokio::sync::Notify;

    use super::*;

    #[test]
    fn new() {
        let cell = AsyncCell::new();
        cell.put("Hello world");
        assert_eq!(cell.take(), Some("Hello world"));

        let cell = AsyncCell::new_with("Hello World");
        assert_eq!(cell.take(), Some("Hello World"));
    }

    #[tokio::test]
    async fn take_out() {
        let cell = AsyncCell::new();
        cell.put("Hello world");
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
        cell.put("Hello world");
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
        cell.put("Hello world");
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
        cell.put("Hello world");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn invalid() {
        let cell: AsyncCell<&str> = AsyncCell::new();

        cell.put("Hello world");
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
        cell.put("Hello world");
        assert_eq!(cell.take(), None);
    }
}
