use std::{future::Future, sync::Arc, time::Duration};

use derive_more::From;
use qbase::param::{ArcParameters, ParameterId};
use thiserror::Error;

use super::validate::ValidateFailure;
use crate::path::ArcPathContexts;

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

#[derive(Debug, From, Error, Clone, Copy)]
pub enum DeferIdleTimeoutFailure {
    #[error("Path validation failed during idle period: {0}")]
    ValidateFailure(ValidateFailure),
}

#[derive(Debug, Error, Clone, Copy)]
#[error("Path has been idle for too long ({} ms) and timed out", self.0.as_millis())]
pub struct IdleTimedOut(Duration);

impl super::Path {
    pub async fn defer_idle_timeout(
        &self,
        config: HeartbeatConfig,
    ) -> Result<(), DeferIdleTimeoutFailure> {
        loop {
            let idle_duration = self.last_active_time.lock().unwrap().elapsed();
            if idle_duration > config.duration {
                core::future::pending::<()>().await;
            } else if idle_duration > config.interval {
                self.validate().await?;
            } else {
                tokio::time::sleep(config.interval.saturating_sub(idle_duration)).await;
            }
        }
    }

    pub fn idle_timeout(
        self: &Arc<Self>,
        parameters: ArcParameters,
        paths: ArcPathContexts,
    ) -> impl Future<Output = Result<(), IdleTimedOut>> {
        let this = self.clone();

        use tokio::time::sleep;

        fn get_local_max_idle_timeout(
            parameters: &ArcParameters,
            paths: &ArcPathContexts,
        ) -> Option<Duration> {
            parameters.lock_guard().ok().and_then(|params| {
                let local_max_idle_timeout = match params.get_local(ParameterId::MaxIdleTimeout)? {
                    Duration::ZERO => Duration::MAX,
                    local_max_idle_timeout => local_max_idle_timeout,
                };
                Some(local_max_idle_timeout.max(paths.max_pto_duration()? * 3))
            })
        }

        async fn get_max_idle_timeout(
            parameters: &ArcParameters,
            paths: &ArcPathContexts,
        ) -> Option<Duration> {
            let (local_max_idle_timeout, remote_max_idle_timeout) =
                parameters.remote_ready().await.ok().and_then(|params| {
                    Some((
                        params.get_local(ParameterId::MaxIdleTimeout)?,
                        params.get_remote(ParameterId::MaxIdleTimeout)?,
                    ))
                })?;

            let max_idle_timeout = match (local_max_idle_timeout, remote_max_idle_timeout) {
                // rfc: https://datatracker.ietf.org/doc/html/rfc9000#name-idle-timeout
                // Each endpoint advertises a max_idle_timeout, but the effective value
                // at an endpoint is computed as the minimum of the two advertised
                // values (or the sole advertised value, if only one endpoint advertises
                // a non-zero value). By announcing a max_idle_timeout, an endpoint
                // commits to initiating an immediate close (Section 10.2) if
                // it abandons the connection prior to the effective value.
                (Duration::ZERO, Duration::ZERO) => Duration::MAX,
                (Duration::ZERO, d) | (d, Duration::ZERO) => d,
                // rfc: https://datatracker.ietf.org/doc/html/rfc9000#name-idle-timeout
                // If a max_idle_timeout is specified by either endpoint in its
                // transport parameters (Section 18.2), the connection is silently
                // closed and its state is discarded when it remains idle for longer
                // than the minimum of the max_idle_timeout value advertised by both
                // endpoints.
                (d1, d2) => d1.min(d2),
            };

            // rfc: https://datatracker.ietf.org/doc/html/rfc9000#name-idle-timeout
            // To avoid excessively small idle timeout periods, endpoints MUST
            // increase the idle timeout period to be at least three times the
            // current Probe Timeout (PTO). This allows for multiple PTOs to expire,
            // and therefore multiple probes to be sent and lost, prior to idle
            // timeout.
            let pto = paths.max_pto_duration()?;
            Some(max_idle_timeout.max(pto * 3))
        }

        async move {
            // if handshake is not done, we use the local max idle timeout
            let local_idle_timeout = async {
                loop {
                    let Some(max_idle_timeout) = get_local_max_idle_timeout(&parameters, &paths)
                    else {
                        // connection in closing/draining state, not idle_timeout
                        return Ok(());
                    };

                    sleep(max_idle_timeout.saturating_sub(this.last_active_time().elapsed())).await;

                    if this.last_active_time().elapsed() > max_idle_timeout {
                        return Err(IdleTimedOut(max_idle_timeout));
                    }
                }
            };

            // once handshake is done, we follow the RFC rules
            let idle_timeout = async {
                loop {
                    let Some(max_idle_timeout) = get_max_idle_timeout(&parameters, &paths).await
                    else {
                        // connection in closing/draining state, not idle_timeout
                        return Ok(());
                    };

                    sleep(max_idle_timeout.saturating_sub(this.last_active_time().elapsed())).await;

                    if this.last_active_time().elapsed() > max_idle_timeout {
                        return Err(IdleTimedOut(max_idle_timeout));
                    }
                }
            };

            tokio::select! {
                // if handshake is not done, we use the local max idle timeout
                idle_timeouted = local_idle_timeout => {
                    idle_timeouted
                }
                // once handshake is done, we follow the RFC rules
                // use _ binding to ignore the result, because the MutexGuard is not Send
                _ = async { _ = parameters.remote_ready().await } => {
                    idle_timeout.await
                }
            }
        }
    }
}
