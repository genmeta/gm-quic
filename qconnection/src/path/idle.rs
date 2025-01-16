use std::{convert::Infallible, sync::Arc, time::Duration};

use qbase::param::{self, ArcParameters};

use super::Path;
use crate::Components;

pub struct Guard {
    path: Arc<Path>,
    defer_timeout: Duration,
    parameters: ArcParameters,
}

impl super::Path {
    pub fn new_guard(self: &Arc<Self>, components: &Components) -> Guard {
        Guard {
            path: self.clone(),
            defer_timeout: Duration::from_secs(30),
            parameters: components.parameters.clone(),
        }
    }
}

impl Guard {
    pub async fn launch(self) -> Result<Infallible, ()> {
        if !self.path.kind.is_initial {
            self.path.validate().await;
        }

        let max_idle_timeout = {
            let param::Pair { local, remote } = self.parameters.clone().await.map_err(|_| ())?;
            match (local.max_idle_timeout(), remote.max_idle_timeout()) {
                // idle timtout after 584,942,417,355 years
                (Duration::ZERO, Duration::ZERO) => Duration::MAX,
                (d, Duration::ZERO) | (Duration::ZERO, d) => d,
                (a, b) => a.min(b),
            }
        };

        loop {
            let since_last_recv = self.path.last_recv_time.lock().unwrap().elapsed();
            if since_last_recv > max_idle_timeout {
                return Err(());
            } else if since_last_recv > self.defer_timeout {
                if !self.path.validate().await {
                    return Err(());
                }
            } else {
                tokio::time::sleep(
                    self.defer_timeout
                        .min(max_idle_timeout)
                        .saturating_sub(since_last_recv),
                )
                .await;
            }
        }
    }
}
