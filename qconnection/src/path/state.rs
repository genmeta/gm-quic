use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    time,
};

use deref_derive::Deref;
use qbase::cid::ArcCidCell;
use qrecovery::reliable::ArcReliableFrameDeque;
use tokio::sync::Notify;

/// Represents the current state of the path.
#[derive(Debug, Clone)]
pub enum PathState {
    Active {
        /// A notifier that is notified when the path becomes inactive.
        notifier: Arc<Notify>,
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
    /// This function initializes the struct with the current time as the initial receive time and
    /// spawns a Tokio task that periodically checks if the path has been inactive for a specified
    /// duration (currently 30 seconds).
    ///
    /// The background task runs in a loop, comparing the current time with the last recorded
    /// receive time. If the difference exceeds the inactivity threshold, the path is transitioned
    /// to the [`InActive`] state and the task terminates.
    ///
    /// [`InActive`]: PathState::InActive
    pub fn new(cid: ArcCidCell<ArcReliableFrameDeque>) -> Self {
        let state = Self {
            state: Arc::new(
                PathState::Active {
                    notifier: Default::default(),
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

    /// Determines if the path has been inactivated.
    ///
    /// If the path is [`InActive`], it returns directly, otherwise, it waits for notification.
    ///
    /// [`InActive`]: PathState::InActive
    pub async fn has_been_inactivated(&self) {
        let inactive = match self.state.lock().unwrap().deref() {
            PathState::Active { notifier, .. } => notifier.clone(),
            PathState::InActive => return,
        };

        inactive.notified().await;
    }

    /// If the state is [`Active`] then transitions the internal state of the associated path to
    /// [`InActive`] and wakes up anynotify all pending tasks waiting on it and retire the cid.
    ///
    /// If the state is [`InActive`] then does nothing.
    ///
    /// [`Active`]: PathState::Active
    /// [`InActive`]: PathState::InActive
    pub fn to_inactive(&self) {
        let mut state = self.state.lock().unwrap();
        match state.deref() {
            PathState::Active {
                notifier, cid_cell, ..
            } => {
                cid_cell.retire();
                notifier.notify_waiters();
                *state = PathState::InActive;
            }
            PathState::InActive => {}
        }
    }

    /// Update the receive time
    ///
    /// This function is used to update the receive timestamp when the path is active.
    /// When the path is active, it gets the current time and updates the path's receive time.
    /// If the path is inactive, no action is taken.
    pub fn update_recv_time(&self) {
        let mut state = self.state.lock().unwrap();
        match state.deref_mut() {
            PathState::Active { recv_time, .. } => *recv_time = time::Instant::now(),
            PathState::InActive => {}
        }
    }
}
