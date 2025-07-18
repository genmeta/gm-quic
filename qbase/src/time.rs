use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::{error::Error, param::ArcParameters};

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

    /// Returns true if the timer has expired.
    ///
    /// Every time the path task wakes up, it needs to check this timer.
    pub fn is_expired(&self, pto: Duration) -> Result<bool, Error> {
        let max_idle_timeout = self
            .parameters
            .lock_guard()?
            .negotiated_max_idle_timeout()
            .unwrap_or(Duration::MAX);
        let max_idle_timeout = max_idle_timeout.max(pto * 3);
        Ok(self.elapsed() >= max_idle_timeout)
    }

    fn elapsed(&self) -> Duration {
        self.last_rcvd_time
            .map_or(Duration::ZERO, |last| last.elapsed())
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
