use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    time,
};

use deref_derive::Deref;
use qbase::cid::ArcCidCell;
use qrecovery::reliable::ArcReliableFrameDeque;
use tokio::sync::Notify;

#[derive(Debug, Clone)]
pub enum PathState {
    Active {
        inactive: Arc<Notify>,
        cid_cell: ArcCidCell<ArcReliableFrameDeque>,
        recv_time: time::Instant,
    },
    InActive,
}

#[derive(Debug, Clone, Deref)]
pub struct ArcPathState {
    state: Arc<Mutex<PathState>>,
}

impl ArcPathState {
    /// Creates a new instance of the struct and spawns a background task to monitor its activity.
    ///
    /// This function initializes the struct with the current time as the initial receive time and spawns a Tokio task that periodically checks if the path has been inactive for a specified duration (currently 30 seconds).
    ///
    /// The background task runs in a loop, comparing the current time with the last recorded receive time. If the difference exceeds the inactivity threshold, the path is transitioned to the InActive state and the task terminates.
    pub fn new(cid: ArcCidCell<ArcReliableFrameDeque>) -> Self {
        let state = Self {
            state: Arc::new(
                PathState::Active {
                    inactive: Default::default(),
                    cid_cell: cid,
                    recv_time: time::Instant::now(),
                }
                .into(),
            ),
        };

        tokio::spawn({
            let state = state.clone();
            async move {
                loop {
                    let now = time::Instant::now();
                    let recv_time = match state.lock().unwrap().deref() {
                        PathState::Active { recv_time, .. } => *recv_time,
                        PathState::InActive => break,
                    };
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
    pub async fn has_been_inactivated(&self) {
        let inactive = match self.state.lock().unwrap().deref() {
            PathState::Active { inactive, .. } => inactive.clone(),
            PathState::InActive => return,
        };

        inactive.notified().await;
    }

    /// Transitions the internal state of the associated path to `InActive` and wakes up any pending tasks waiting on it.
    /// and retire the cid.
    ///
    /// This function acquires a lock on the internal mutex protecting the path's state. If the current state is `Pending`,
    /// it indicates that a task is waiting for the path to become active. In this case, the associated waker is invoked
    /// to wake up the waiting task.
    ///
    /// Regardless of the initial state, the function sets the state to `InActive`, signifying that the path is no longer
    /// actively being processed or monitored.
    pub fn to_inactive(&self) {
        let mut state = self.state.lock().unwrap();
        match state.deref() {
            PathState::Active {
                inactive, cid_cell, ..
            } => {
                cid_cell.retire();
                inactive.notify_waiters();
                *state = PathState::InActive;
            }
            PathState::InActive => {}
        }
    }

    pub fn update_recv_time(&self) {
        let mut state = self.state.lock().unwrap();
        match state.deref_mut() {
            PathState::Active { recv_time, .. } => *recv_time = time::Instant::now(),
            PathState::InActive => {}
        }
    }
}
