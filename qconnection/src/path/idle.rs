use std::{future::Future, sync::Arc, time::Duration};

use qbase::param::ParameterId;

use crate::Components;

/// Keep alive configuration.
///
/// default: disabled.
///
/// That is, path validation is initiated every 10 seconds when the path is idle.
/// the path is deactivated if the validation fails.
/// If the path is idle for more than 300 seconds (no data is received for more than 300 seconds),
/// the keep-alive process will be terminated.
#[derive(Debug, Clone, Copy)]
pub struct HeartbeatConfig {
    duration: Duration,
    interval: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self::ZERO
    }
}

impl HeartbeatConfig {
    /// Disabled
    pub const ZERO: Self = Self {
        duration: Duration::ZERO,
        interval: Duration::ZERO,
    };

    pub const fn new(time: Duration) -> Self {
        Self::new_with_interval(time, Duration::from_secs(10))
    }

    pub const fn new_with_interval(time: Duration, interval: Duration) -> Self {
        Self {
            duration: time,
            interval,
        }
    }
}

impl super::Path {
    pub async fn defer_idle_timeout(&self, config: HeartbeatConfig) {
        loop {
            let idle_duration = self.last_active_time.lock().unwrap().elapsed();
            if idle_duration > config.duration {
                core::future::pending::<()>().await;
            } else if idle_duration > config.interval {
                if !self.validate().await {
                    return;
                }
            } else {
                tokio::time::sleep(config.interval.saturating_sub(idle_duration)).await;
            }
        }
    }

    pub fn idle_timeout(self: &Arc<Self>, components: &Components) -> impl Future<Output = bool> {
        let parameters = components.parameters.clone();
        let this = self.clone();
        async move {
            let (Ok(local_max_idle_timeout), Ok(remote_max_idle_timeout)) = (
                parameters.get_local_as(ParameterId::MaxIdleTimeout),
                parameters.get_remote_as(ParameterId::MaxIdleTimeout).await,
            ) else {
                // if the connection enter closing state in initial space is not idle_timeout
                return false;
            };
            let max_idle_timeout = match (local_max_idle_timeout, remote_max_idle_timeout) {
                (Duration::ZERO, Duration::ZERO) => Duration::MAX,
                (Duration::ZERO, d) | (d, Duration::ZERO) => d,
                (d1, d2) => d1.min(d2),
            };

            loop {
                let idle_duration = this.last_active_time.lock().unwrap().elapsed();
                if idle_duration > max_idle_timeout {
                    return true;
                } else {
                    tokio::time::sleep(max_idle_timeout.saturating_sub(idle_duration)).await;
                }
            }
        }
    }
}
