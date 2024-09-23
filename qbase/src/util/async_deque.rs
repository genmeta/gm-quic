use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use futures::Stream;

use crate::frame::SendFrame;

/// AsyncDeque is a deque that can be used in async context.
///
/// It is a wrapper around VecDeque, with the ability to be popped in async context.
/// That is, when calling pop on an empty queue,
/// it will suspend the current task until a new element is pushed in.
/// In a sense, it is a combination of the sender and receiver ends of an mpsc channel,
/// and the sender can insert in both directions.
#[derive(Debug)]
struct AsyncDeque<T> {
    queue: Option<VecDeque<T>>,
    waker: Option<Waker>,
}

impl<T> AsyncDeque<T> {
    /// Insert an element at the back of the queue,
    /// and wake up the `pop` task registered by [AsyncDeque::poll_pop] if necessary.
    fn push_back(&mut self, value: T) {
        if let Some(queue) = &mut self.queue {
            queue.push_back(value);
            if let Some(waker) = self.waker.take() {
                waker.wake();
            }
        }
    }

    /// Insert an element at the front of the deque,
    /// and wake up the `pop` task registered by [AsyncDeque::poll_pop] if necessary.
    fn push_front(&mut self, value: T) {
        if let Some(queue) = &mut self.queue {
            queue.push_front(value);
            if let Some(waker) = self.waker.take() {
                waker.wake();
            }
        }
    }

    /// Poll the next element in the queue.
    ///
    /// If the deque is empty, the current `pop` will be suspended until a new element is pushed in.
    ///
    /// If the deque is closed, the `pop` task will get the final `None` element,
    /// indicating that the queue has been closed,
    /// and the `pop` task should stop.
    fn poll_pop(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        match &mut self.queue {
            Some(queue) => {
                if let Some(frame) = queue.pop_front() {
                    Poll::Ready(Some(frame))
                } else if let Some(ref waker) = self.waker {
                    if !waker.will_wake(cx.waker()) {
                        panic!("Multiple tasks are attempting to wait on the same AsyncDeque.");
                    }
                    // same waker, no need to update again
                    Poll::Pending
                } else {
                    // no waker, register the current waker
                    self.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
            None => Poll::Ready(None),
        }
    }

    /// Return the number of elements in the queue.
    fn len(&self) -> usize {
        self.queue.as_ref().map(|v| v.len()).unwrap_or(0)
    }

    /// Return whether the queue is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Close the deque, and wake up the `pop` task registered by [AsyncDeque::poll_pop] nescessary.
    ///
    /// This will cause the `pop`` task get the final `None` element,
    /// indicating that the queue has been closed,
    /// and the `pop`` task should stop.
    ///
    /// # Examples
    pub fn close(&mut self) {
        self.queue = None;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

/// A shared deque that can be used in async context.
///
/// It is a wrapper around VecDeque, with the ability to be popped in async context.
/// That is, when calling pop on an empty queue,
/// it will suspend the current task until a new element is pushed in.
/// In a sense, it is a combination of the sender and receiver ends of an mpsc channel,
/// and the sender can insert in both directions.
#[derive(Debug)]
pub struct ArcAsyncDeque<T>(Arc<Mutex<AsyncDeque<T>>>);

impl<T> ArcAsyncDeque<T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(AsyncDeque {
            queue: Some(VecDeque::with_capacity(8)),
            waker: None,
        })))
    }

    fn lock_guard(&self) -> MutexGuard<'_, AsyncDeque<T>> {
        self.0.lock().unwrap()
    }

    /// Insert an element at the front of the queue,
    /// and wake up the `pop` task  if registered by [ArcAsyncDeque::pop].
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::ArcAsyncDeque;
    ///
    /// let mut deque = ArcAsyncDeque::new();
    /// deque.push_front(1);
    /// deque.push_front(2);
    /// assert_eq!(deque.len(), 2);
    /// ```
    pub fn push_front(&self, value: T) {
        self.lock_guard().push_front(value);
    }

    /// Insert an element at the back of the queue,
    /// and wake up the `pop` task  if registered by [ArcAsyncDeque::pop].
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::ArcAsyncDeque;
    ///
    /// let mut deque = ArcAsyncDeque::new();
    /// deque.push_back(1);
    /// deque.push_back(2);
    /// assert_eq!(deque.len(), 2);
    /// ```
    pub fn push_back(&self, value: T) {
        self.lock_guard().push_back(value);
    }

    /// Asynchronously pop the next element in the queue.
    ///
    /// If the deque is empty, the current `pop` will be suspended until a new element is pushed in.
    ///
    /// If the deque is closed, the `pop` task will get the final `None` element,
    /// indicating that the queue has been closed,
    /// and the `pop` task should stop.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::ArcAsyncDeque;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///    let mut deque = ArcAsyncDeque::new();
    ///
    ///     tokio::spawn({
    ///         let deque = deque.clone();
    ///         async move {
    ///             assert_eq!(deque.pop().await, Some(1));
    ///         }
    ///     });
    ///
    ///     deque.push_back(1);
    /// }
    /// ```
    pub fn pop(&self) -> Self {
        self.clone()
    }

    /// Poll pop the next element in the queue.
    ///
    /// If the deque is empty, the current `pop` will be suspended until a new element is pushed in.
    ///
    /// If the deque is closed, the `pop` task will get the final `None` element,
    /// indicating that the queue has been closed,
    /// and the `pop` task should stop.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::ArcAsyncDeque;
    /// use futures::task::{Poll, noop_waker};
    ///
    /// let waker = noop_waker();
    /// let mut cx = std::task::Context::from_waker(&waker);
    /// let mut deque = ArcAsyncDeque::new();
    /// assert_eq!(deque.poll_pop(&mut cx), Poll::Pending);
    ///
    /// deque.push_back(1);
    /// assert_eq!(deque.poll_pop(&mut cx), Poll::Ready(Some(1)));
    /// assert_eq!(deque.poll_pop(&mut cx), Poll::Pending);
    /// ```
    pub fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.lock_guard().poll_pop(cx)
    }

    /// Return the number of elements in the queue.
    pub fn len(&self) -> usize {
        self.lock_guard().len()
    }

    /// Return whether the queue is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::ArcAsyncDeque;
    ///
    /// let mut deque = ArcAsyncDeque::new();
    /// assert!(deque.is_empty());
    ///
    /// deque.push_back(1);
    /// assert!(!deque.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.lock_guard().is_empty()
    }

    /// Close the deque, and wake up the `pop` task if registered by [ArcAsyncDeque::poll_pop].
    ///
    /// This will cause the `pop` task get the final `None` element,
    /// indicating that the queue has been closed,
    /// and the `pop` task should stop.
    ///
    /// # Examples
    ///
    /// ```
    /// use qbase::util::ArcAsyncDeque;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///    let mut deque = ArcAsyncDeque::new();
    ///
    ///     tokio::spawn({
    ///         let deque = deque.clone();
    ///         async move {
    ///             assert_eq!(deque.pop().await, Some(1));
    ///             assert_eq!(deque.pop().await, None);
    ///         }
    ///     });
    ///
    ///     deque.push_back(1);
    ///     deque.close();
    /// }
    /// ```
    pub fn close(&self) {
        self.lock_guard().close();
    }
}

impl<T> Default for ArcAsyncDeque<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for ArcAsyncDeque<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Future for ArcAsyncDeque<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll_pop(cx)
    }
}

impl<T: Unpin> Stream for AsyncDeque<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().poll_pop(cx)
    }
}

impl<T> Extend<T> for &ArcAsyncDeque<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.send_frame(iter);
    }
}

impl<F> SendFrame<F> for ArcAsyncDeque<F> {
    fn send_frame<I: IntoIterator<Item = F>>(&self, iter: I) {
        let mut guard = self.0.lock().unwrap();
        if let Some(queue) = &mut guard.queue {
            queue.extend(iter);
            if let Some(waker) = guard.waker.take() {
                waker.wake();
            }
        }
    }
}
