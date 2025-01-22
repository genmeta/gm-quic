use std::{future::Future, sync::Arc, time::Duration};

use qbase::param::{self};

use crate::Components;

impl super::Path {
    pub async fn defer_idle_timeout(&self, defer_timeout: Duration) {
        loop {
            let idle_duration = self.last_recv_time.lock().unwrap().elapsed();
            if idle_duration > defer_timeout {
                tracing::trace!("try to defer idle timeout");
                if !self.validate().await {
                    return;
                }
            } else {
                tokio::time::sleep(defer_timeout.saturating_sub(idle_duration)).await;
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
                    tracing::trace!("path idle timeout");
                    return;
                } else {
                    tokio::time::sleep(max_idle_timeout.saturating_sub(idle_duration)).await;
                }
            }
        }
    }
}
