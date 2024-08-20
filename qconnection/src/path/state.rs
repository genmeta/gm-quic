use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time,
};

use deref_derive::Deref;

#[derive(Debug, Clone, Default)]
pub enum PathState {
    #[default]
    Active,
    Pending(Vec<Waker>),
    InActive,
}

#[derive(Debug, Clone, Deref)]
pub struct ArcPathState {
    #[deref]
    recv_time: Arc<Mutex<time::Instant>>,
    state: Arc<Mutex<PathState>>,
}

impl ArcPathState {
    /// Creates a new instance of the struct and spawns a background task to monitor its activity.
    ///
    /// This function initializes the struct with the current time as the initial receive time and spawns a Tokio task that periodically checks if the path has been inactive for a specified duration (currently 30 seconds).
    ///
    /// The background task runs in a loop, comparing the current time with the last recorded receive time. If the difference exceeds the inactivity threshold, the path is transitioned to the InActive state and the task terminates.
    pub fn new() -> Self {
        let state = Self {
            recv_time: Arc::new(Mutex::new(time::Instant::now())),
            state: Default::default(),
        };

        tokio::spawn({
            let state = state.clone();
            async move {
                loop {
                    let now = time::Instant::now();
                    let recv_time = *state.lock().unwrap();
                    // TODO: 失活时间暂定30s
                    if now.duration_since(recv_time) >= time::Duration::from_secs(30) {
                        state.to_inactive();
                        break;
                    }
                    tokio::time::sleep_until((recv_time + time::Duration::from_secs(30)).into())
                        .await
                }
            }
        });

        state
    }
    /// Creates a new `ArcPathState` that shares the underlying state with the current instance.
    ///
    /// This function effectively returns a clone of the `ArcPathState`, allowing multiple consumers to monitor the same
    /// underlying `PathState` without affecting each other. This is useful for scenarios where multiple tasks might be
    /// interested in knowing if the path has been inactivated.
    ///
    /// **Note:** This function does not modify the internal state in any way. It simply provides another handle to the
    /// existing shared state.
    pub fn has_been_inactivated(&self) -> Self {
        self.clone()
    }

    /// Transitions the internal state of the associated path to `InActive` and wakes up any pending tasks waiting on it.
    ///
    /// This function acquires a lock on the internal mutex protecting the path's state. If the current state is `Pending`,
    /// it indicates that a task is waiting for the path to become active. In this case, the associated waker is invoked
    /// to wake up the waiting task.
    ///
    /// Regardless of the initial state, the function sets the state to `InActive`, signifying that the path is no longer
    /// actively being processed or monitored.
    pub fn to_inactive(&self) {
        let mut guard = self.state.lock().unwrap();
        if let PathState::Pending(ref mut wakers) = *guard {
            let wakers = std::mem::take(wakers);
            *guard = PathState::InActive;
            for waker in wakers {
                waker.wake();
            }
        }
    }
}

impl Future for ArcPathState {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.state.lock().unwrap();

        match *guard {
            PathState::Active => *guard = PathState::Pending(vec![cx.waker().clone()]),
            PathState::Pending(ref mut wakers) => wakers.push(cx.waker().clone()),
            PathState::InActive => return Poll::Ready(()),
        }
        Poll::Pending
    }
}
