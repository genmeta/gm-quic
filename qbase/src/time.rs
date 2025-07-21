use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use thiserror::Error;

use crate::param::ArcParameters;

#[derive(Debug)]
struct DeferIdleTimer {
    defer_idle_timeout: Duration,
    last_effective_comm: Option<Instant>,
}

impl DeferIdleTimer {
    /// Creates a new `ArcDeferIdleTimer` with the specified defer idle timeout.
    fn new(defer_idle_timeout: Duration) -> Self {
        Self {
            defer_idle_timeout,
            last_effective_comm: None,
        }
    }

    /// Resets the timer to the current time after effective communication.
    ///
    /// Effective communication is defined as sending or receiving a packet with a valid payload,
    /// which does not include packets that only contain Padding, Ping, or Ack.
    fn renew(&mut self) {
        // Even if the timer is expired, it can be updated to the current time
        // within the max idle timeout.
        self.last_effective_comm = Some(Instant::now());
    }

    /// Returns true if the timer has expired.
    ///
    /// When sending a heartbeat packet that includes a ping, this method should be called first.
    /// If it returns true, sending a ping packet is prohibited.
    fn is_expired(&self) -> bool {
        self.elapsed() >= self.defer_idle_timeout
    }

    fn elapsed(&self) -> Duration {
        self.last_effective_comm
            .map_or(Duration::ZERO, |last| last.elapsed())
    }
}

/// A shared timer for connection-level defer idle timeout.
///
/// It is not necessary to set a timer task to check for timeouts,
/// because its timeout event is not critical.
/// After restricting the sending of ping packets, the `MaxIdleTimer`
/// will check for a timeout and automatically delete the path if it occurs.
#[derive(Debug, Clone)]
pub struct ArcDeferIdleTimer(Arc<Mutex<DeferIdleTimer>>);

impl ArcDeferIdleTimer {
    /// Creates a new `ArcDeferIdleTimer` with the specified defer idle timeout.
    pub fn new(defer_idle_timeout: Duration) -> Self {
        Self(Arc::new(Mutex::new(DeferIdleTimer::new(
            defer_idle_timeout,
        ))))
    }

    /// Resets the timer to the current time after effective communication.
    ///
    /// Effective communication is defined as sending or receiving a packet with a valid payload,
    /// which does not include packets that only contain Padding, Ping, or Ack.
    pub fn renew_on_effective_communicated(&self) {
        self.0.lock().unwrap().renew()
    }

    /// Returns true if the timer has expired.
    ///
    /// When sending a heartbeat packet that includes a ping, this method should be called first.
    /// If it returns true, sending a ping packet is prohibited.
    pub fn is_expired(&self) -> bool {
        self.0.lock().unwrap().is_expired()
    }
}

/// A maximum idle timer for each path.
#[derive(Debug)]
pub struct MaxIdleTimer {
    parameters: ArcParameters,
    last_rcvd_time: Option<Instant>,
}

#[derive(Debug, Error)]
#[error("Path has been idle for too long({} ms)", self.idle_for.as_millis())]
pub struct IdleTimedOut {
    last_rcvd_time: Option<Instant>,
    idle_for: Duration,
}

impl IdleTimedOut {
    pub fn last_rcvd_time(&self) -> Option<Instant> {
        self.last_rcvd_time
    }

    pub fn idle_for(&self) -> Duration {
        self.idle_for
    }
}

impl MaxIdleTimer {
    /// Creates a new `MaxIdleTimer` with the specified parameters.
    pub(crate) fn new(parameters: ArcParameters) -> Self {
        Self {
            parameters,
            last_rcvd_time: None,
        }
    }

    /// Resets the timer to the current time upon receiving a packet.
    pub fn renew_on_received_1rtt(&mut self) {
        self.last_rcvd_time = Some(Instant::now());
    }

    /// Returns err if the path has been idle for too long.
    ///
    /// Every time the path task wakes up, it needs to check this timer.
    pub fn check(&self, pto: Duration) -> Result<(), IdleTimedOut> {
        let Ok(parameters) = self.parameters.lock_guard() else {
            return Ok(());
        };

        let Some(max_idle_timeout) = parameters.negotiated_max_idle_timeout() else {
            return Ok(());
        };

        let max_idle_timeout = max_idle_timeout.max(pto * 3);

        let Some(last_rcvd_time) = self.last_rcvd_time else {
            return Ok(());
        };

        let since_last_rcvd = last_rcvd_time.elapsed();

        if since_last_rcvd >= max_idle_timeout {
            return Err(IdleTimedOut {
                last_rcvd_time: Some(last_rcvd_time),
                idle_for: since_last_rcvd,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ArcMaxIdleTimer(Arc<Mutex<MaxIdleTimer>>);

impl From<MaxIdleTimer> for ArcMaxIdleTimer {
    fn from(timer: MaxIdleTimer) -> Self {
        ArcMaxIdleTimer(Arc::new(Mutex::new(timer)))
    }
}

impl ArcMaxIdleTimer {
    /// Resets the timer to the current time upon receiving a packet.
    pub fn renew_on_received_1rtt(&self) {
        self.0.lock().unwrap().renew_on_received_1rtt();
    }

    /// Returns err if the path has been idle for too long.
    pub fn check(&self, pto: Duration) -> Result<(), IdleTimedOut> {
        self.0.lock().unwrap().check(pto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defer_idle_timer() {
        let timer = ArcDeferIdleTimer::new(Duration::from_millis(100));
        timer.renew_on_effective_communicated();
        assert!(!timer.is_expired());
        std::thread::sleep(Duration::from_millis(150));
        assert!(timer.is_expired());
    }
}
