use std::{future::Future, sync::Arc, time::Duration};

use qbase::param::{self};

use crate::Components;

/// Keep alive configuration.
///
/// default: `300s` timeout, `10s` interval
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
        Self::new(Duration::from_secs(300))
    }
}

impl HeartbeatConfig {
    pub fn new(time: Duration) -> Self {
        Self::new_with_interval(time, Duration::from_secs(10))
    }

    pub fn new_with_interval(time: Duration, interval: Duration) -> Self {
        Self {
            duration: time,
            interval,
        }
    }

    pub fn disabled() -> Self {
        Self::new_with_interval(Duration::MAX, Duration::MAX)
    }
}

impl super::Path {
    pub async fn defer_idle_timeout(&self, config: HeartbeatConfig) {
        loop {
            let idle_duration = self.last_recv_time.lock().unwrap().elapsed();
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

    pub fn idle_timeout(
        self: &Arc<Self>,
        components: &Components,
    ) -> impl Future<Output = ()> + use<> {
        let parameters = components.parameters.clone();
        let this = self.clone();
        async move {
            let Ok(param::Pair { local, remote }) = parameters.await else {
                return;
            };
            let max_idle_timeout = match (local.max_idle_timeout(), remote.max_idle_timeout()) {
                (Duration::ZERO, Duration::ZERO) => Duration::MAX,
                (Duration::ZERO, d) | (d, Duration::ZERO) => d,
                (d1, d2) => d1.min(d2),
            };

            loop {
                let idle_duration = this.last_recv_time.lock().unwrap().elapsed();
                if idle_duration > max_idle_timeout {
                    return;
                } else {
                    tokio::time::sleep(max_idle_timeout.saturating_sub(idle_duration)).await;
                }
            }
        }
    }
}
