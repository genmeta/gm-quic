use std::{
    collections::VecDeque,
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use deref_derive::{Deref, DerefMut};
use futures::task::AtomicWaker;

#[derive(Debug, Default, Clone)]
pub enum RawAsyncCell<T> {
    #[default]
    Pending,
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
        matches!(self, Self::Pending)
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
        Ok(core::mem::replace(self, RawAsyncCell::Ready(item)).take())
    }

    #[inline]
    pub fn take(&mut self) -> Option<T> {
        match std::mem::replace(self, RawAsyncCell::Pending) {
            RawAsyncCell::Pending => None,
            RawAsyncCell::Invalid => {
                *self = RawAsyncCell::Invalid;
                None
            }
            RawAsyncCell::Ready(item) => Some(item),
        }
    }

    #[inline]
    pub fn invalid(&mut self) {
        *self = Self::Invalid
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
struct Wakers(VecDeque<Arc<AtomicWaker>>);

impl Default for Wakers {
    fn default() -> Self {
        // in most case, there will only be one waker in deque
        Self(VecDeque::with_capacity(1))
    }
}

impl Wakers {
    fn wait(&mut self, waker: &Waker) -> Wait {
        let atomic_waker = AtomicWaker::new();
        atomic_waker.register(waker);
        let waker = Arc::new(atomic_waker);

        self.0.push_back(waker.clone());
        Wait(waker)
    }

    /// # Safety
    ///
    /// This method is not Cancel Safe!
    ///
    /// If the future canceled, other tasks will not wake up
    unsafe fn wait_unsafe(&mut self, waker: &Waker) {
        let atomic_waker = AtomicWaker::new();
        atomic_waker.register(waker);
        let waker = Arc::new(atomic_waker);
        self.0.push_back(waker.clone());
    }

    fn wake_one(&mut self) {
        while let Some(waker) = self.0.pop_front() {
            if let Some(waker) = waker.take() {
                waker.wake();
                break;
            }
        }
    }
}

struct Wait(Arc<AtomicWaker>);

impl Drop for Wait {
    fn drop(&mut self) {
        self.0.take();
    }
}

#[derive(Debug)]
pub struct AsyncCell<T> {
    state: Mutex<RawAsyncCell<T>>,
    wakers: Mutex<Wakers>,
}

impl<T> Default for AsyncCell<T> {
    fn default() -> Self {
        Self {
            state: Default::default(),
            wakers: Default::default(),
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
            state: Mutex::new(RawAsyncCell::Ready(item)),
            ..Default::default()
        }
    }

    #[inline]
    pub fn is_pending(&self) -> bool {
        self.get_inner().is_pending()
    }

    #[inline]
    pub fn is_ready(&self) -> bool {
        self.get_inner().is_ready()
    }

    #[inline]
    pub fn is_invalid(&self) -> bool {
        self.get_inner().is_invalid()
    }

    #[inline]
    pub fn write(&self, item: T) -> Result<Option<T>, T> {
        self.get_inner().write(item)
    }
    #[inline]
    pub fn take(&self) -> Option<T> {
        self.get_inner().take()
    }

    /// Invalid the state
    ///
    /// return [`true`] if the state is invalided before this method is called
    #[inline]
    pub fn invalid(&self) {
        self.get_inner().invalid();
    }

    #[inline]
    pub fn get_inner(&self) -> Ref<T> {
        let raw = self.state.lock().unwrap();
        Ref { raw, cell: self }
    }

    #[inline]
    pub fn get(&self) -> GetRef<'_, T> {
        GetRef {
            cell: self,
            wait: None,
        }
    }

    /// # Safety
    ///
    /// This method is not Cancel Safe.
    ///
    /// If the future canceled, other take will not wake anymore.
    #[inline]
    pub unsafe fn poll_get_unsafe<'a>(&'a self, cx: &mut Context) -> Poll<Ref<'a, T>> {
        let raw = self.state.lock().unwrap();

        if raw.is_pending() {
            unsafe { self.wakers.lock().unwrap().wait_unsafe(cx.waker()) };
            return Poll::Pending;
        }
        Poll::Ready(Ref { raw, cell: self })
    }
}

#[derive(Debug, Deref, DerefMut)]
pub struct Ref<'c, T> {
    #[deref]
    raw: MutexGuard<'c, RawAsyncCell<T>>,
    cell: &'c AsyncCell<T>,
}

impl<T> Drop for Ref<'_, T> {
    fn drop(&mut self) {
        if self.raw.is_ready() || self.raw.is_invalid() {
            // If the inner state is locked in other task, wake the GetRef will only update the waker
            self.cell.wakers.lock().unwrap().wake_one()
        }
    }
}

pub struct GetRef<'s, T> {
    cell: &'s AsyncCell<T>,
    wait: Option<Wait>,
}

impl<'c, T> GetRef<'c, T> {
    fn register_waker(&mut self, waker: &Waker) {
        match &self.wait {
            Some(wait) => wait.0.register(waker),
            None => self.wait = Some(self.cell.wakers.lock().unwrap().wait(waker)),
        }
    }

    pub fn poll(&mut self, cx: &mut Context) -> Poll<Ref<'c, T>> {
        let cell = self.cell;
        let Ok(raw) = cell.state.try_lock() else {
            self.register_waker(cx.waker());
            return Poll::Pending;
        };
        if raw.is_pending() {
            self.register_waker(cx.waker());
            return Poll::Pending;
        }
        Poll::Ready(Ref { raw, cell })
    }
}

impl<T> Unpin for GetRef<'_, T> {}

impl<'c, T> Future for GetRef<'c, T> {
    type Output = Ref<'c, T>;

    #[inline]
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().poll(cx)
    }
}

#[cfg(test)]
mod tests {

    use tokio::sync::Notify;

    use super::*;

    impl<T> AsyncCell<T> {
        fn poll_once(&self, cx: &mut Context) -> Poll<Ref<T>> {
            self.get().poll(cx)
        }
    }

    #[test]
    fn new() {
        let cell = AsyncCell::new();
        assert!(cell.is_pending());
        assert_eq!(cell.get_inner().as_ref(), None);
        assert_eq!(cell.get_inner().as_mut(), None);

        assert_eq!(cell.write("Hello world"), Ok(None));
        assert!(cell.is_ready());
        assert!(cell.get_inner().as_ref().is_some());
        *cell.get_inner().as_mut().unwrap() = "Hello World";
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
                    core::future::poll_fn(|cx| Poll::Ready(cell.poll_once(cx))).await,
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

        let poll = core::future::poll_fn(|cx| Poll::Ready(cell.poll_once(cx))).await;
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
                    core::future::poll_fn(|cx| Poll::Ready(cell.poll_once(cx))).await,
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
