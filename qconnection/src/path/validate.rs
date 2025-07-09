use std::{sync::atomic::Ordering, time::Duration};

use qbase::frame::PathChallengeFrame;
use qcongestion::Transport;
use thiserror::Error;
use tokio::time::Instant;

#[derive(Debug, Error, Clone, Copy)]
pub enum ValidateFailure {
    #[error(
        "Path validation abort due to path inactivity by other reasons(usually connection closed)"
    )]
    PathInactive,
    #[error("Path validation failed after {0:?}")]
    Timeout(Duration),
}

impl super::Path {
    pub fn skip_validation(&self) {
        self.validated.store(true, Ordering::Release);
    }

    pub async fn validate(&self) -> Result<(), ValidateFailure> {
        let challenge = PathChallengeFrame::random();
        let start = Instant::now();
        for i in 0..5 {
            let timeout_duration = self.cc().get_pto(qbase::Epoch::Data) * (1 << i);
            self.challenge_sndbuf.write(challenge);
            match tokio::time::timeout(timeout_duration, self.response_rcvbuf.receive()).await {
                Ok(Some(response)) if *response == *challenge => {
                    self.anti_amplifier.grant();
                    return Ok(());
                }
                // 外部发生变化，导致路径验证任务作废
                Ok(None) => return Err(ValidateFailure::PathInactive),
                // 超时或者收到不对的response，按"停-等协议"，继续再发一次Challenge，最多3次
                _ => continue,
            }
        }
        Err(ValidateFailure::Timeout(start.elapsed()))
    }
}
