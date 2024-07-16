use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::BufMut;
use futures::Future;
use qbase::{
    frame::{
        io::{WritePathChallengeFrame, WritePathResponseFrame},
        BeFrame, PathChallengeFrame, PathResponseFrame,
    },
    util::TransportLimit,
};

/// Path validator, used to verify the validity of the path.
#[derive(Debug)]
pub(crate) enum ValidateState {
    /// Challenging, `true` the challenge frame has been sent, otherwise it has
    /// not been sent.
    Challenging(PathChallengeFrame, bool),
    /// Rechallenging, `true` the challenge frame has been sent, otherwise it has
    /// not been sent.
    Rechallenging(PathChallengeFrame, bool),
    /// Verification successful
    Success,
    /// When no Challenge Response frame is received within a period of time, the
    /// verification is considered failed.
    Failure,
}

impl Default for ValidateState {
    fn default() -> Self {
        Self::Challenging(PathChallengeFrame::random(), false)
    }
}

impl ValidateState {
    fn challenge(&mut self) {
        match self {
            ValidateState::Challenging(_, _) | ValidateState::Rechallenging(_, _) => {}
            ValidateState::Success => {
                *self = ValidateState::Rechallenging(PathChallengeFrame::random(), false);
            }
            ValidateState::Failure => unreachable!("need not challenge again"),
        }
    }

    fn need_send_challenge(&self) -> Option<&PathChallengeFrame> {
        match self {
            ValidateState::Challenging(challenge, false) => Some(challenge),
            ValidateState::Rechallenging(challenge, false) => Some(challenge),
            _ => None,
        }
    }

    /// 必须在need_send_challenge之后调用，且确实发送了PathChallengeFrame，才可调用
    fn on_challenge_sent(&mut self) {
        match self {
            ValidateState::Challenging(_, pkt) | ValidateState::Rechallenging(_, pkt) => {
                *pkt = true;
            }
            _ => unreachable!("no reason to send challenge frame"),
        }
    }

    /// 曾经发送PathChallengeFrame的数据包可能丢了，需要改变状态，触发重传
    fn may_loss(&mut self) {
        match self {
            ValidateState::Challenging(_, pkt) | ValidateState::Rechallenging(_, pkt) => {
                *pkt = false;
            }
            _ => (),
        }
    }

    fn on_response(&mut self, response: &PathResponseFrame) {
        match self {
            ValidateState::Challenging(challenge, _) => {
                if **challenge == **response {
                    *self = ValidateState::Success;
                }
            }
            ValidateState::Rechallenging(challenge, _) => {
                if **challenge == **response {
                    *self = ValidateState::Success;
                }
            }
            _ => (),
        }
    }
}

/// Mutex can be replaced by RwLock
#[derive(Debug, Clone, Default)]
pub struct Validator {
    state: Arc<Mutex<ValidateState>>,
    waker: Option<Waker>,
}

impl Validator {
    pub fn challenge(&self) {
        self.state.lock().unwrap().challenge();
    }

    pub fn write_challenge(&self, limit: &mut TransportLimit, mut buf: &mut [u8]) -> usize {
        let origin_size = limit.available();
        let remain = buf.remaining_mut();
        if let Some(challenge) = self.state.lock().unwrap().need_send_challenge() {
            if origin_size >= challenge.encoding_size() {
                buf.put_path_challenge_frame(challenge);
            }
        }
        remain - buf.remaining_mut()
    }

    /// Record space and pn to marks it is sent
    pub fn on_challenge_sent(&self) {
        self.state.lock().unwrap().on_challenge_sent();
    }

    /// Return a `Future` that can be used to poll the state of the validator.
    ///
    /// The `Future` resolves to `true` if the validator is successful, and `false` otherwise.
    /// If the verification is not completed, the "Future" will wait for the state to
    /// transition to the final state, according to the timeout specified in `on_challenge_sent`
    pub fn get_validate_state(&self) -> ValidatorState {
        ValidatorState(self.clone())
    }

    pub fn may_loss(&self) {
        self.state.lock().unwrap().may_loss();
    }

    pub fn on_response(&mut self, response: &PathResponseFrame) {
        self.state.lock().unwrap().on_response(response);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    pub fn validated(&mut self) {
        *self.state.lock().unwrap() = ValidateState::Success;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    pub fn is_validated(&self) -> bool {
        matches!(*self.state.lock().unwrap(), ValidateState::Success)
    }

    /// Spawns a new Tokio task to fail status after the specified timeout.
    /// Even if it is retransmitted, as long as the verification is successful once
    /// within the specified timeout, the final verification is guaranteed
    /// to be successful.
    pub fn set_timeout(&self, timeout: Duration) {
        tokio::spawn({
            let state = self.state.clone();
            let mut validator = self.clone();

            async move {
                if tokio::time::timeout(timeout, validator.get_validate_state())
                    .await
                    .is_err()
                {
                    let mut state = state.lock().unwrap();
                    *state = ValidateState::Failure;
                    if let Some(waker) = validator.waker.take() {
                        waker.wake();
                    }
                };
            }
        });
    }
}

pub struct ValidatorState(Validator);

impl Future for ValidatorState {
    type Output = bool;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let s = self.get_mut();
        match *s.0.state.lock().unwrap() {
            ValidateState::Success => Poll::Ready(true),
            ValidateState::Failure => Poll::Ready(false),
            _ => {
                s.0.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

#[derive(Debug, Default)]
enum ResponseState {
    #[default]
    None,
    // 收到路径挑战帧，如果上个挑战没完成就来了新的挑战，意味着旧挑战
    // 作废，则更新挑战，后续只处理新挑战
    // 响应挑战，响应帧在哪个包号里（只可能在1RTT数据包中），用于防丢
    // 如果丢包重传，包号要更新
    Challenged(PathChallengeFrame, Option<u64>),
}

impl ResponseState {
    fn on_challenge(&mut self, challenge: PathChallengeFrame) {
        match self {
            ResponseState::None => {
                *self = ResponseState::Challenged(challenge, None);
            }
            ResponseState::Challenged(old_challenge, pkt) => {
                if *old_challenge != challenge {
                    *old_challenge = challenge;
                    *pkt = None;
                }
            }
        }
    }

    fn need_response(&self) -> Option<PathResponseFrame> {
        match self {
            ResponseState::Challenged(challenge, None) => Some(challenge.into()),
            _ => None,
        }
    }

    fn waiting_ack(&self) -> Option<u64> {
        if let ResponseState::Challenged(_, Some(pkt)) = self {
            Some(*pkt)
        } else {
            None
        }
    }

    fn on_response_sent(&mut self, pn: u64) {
        match self {
            ResponseState::Challenged(_, pkt) => {
                assert_eq!(*pkt, None);
                *pkt = Some(pn);
            }
            _ => unreachable!("would not send path response frame"),
        }
    }

    fn acked(&mut self) {
        *self = ResponseState::None;
    }

    fn may_loss_pkt(&mut self, pn: u64) {
        if let ResponseState::Challenged(_, pkt) = self {
            if *pkt == Some(pn) {
                *pkt = None;
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Transponder(Arc<Mutex<ResponseState>>);

impl Transponder {
    pub fn on_challenge(&self, challenge: PathChallengeFrame) {
        self.0.lock().unwrap().on_challenge(challenge);
    }

    pub fn write_response(&self, limit: &mut TransportLimit, mut buf: &mut [u8]) -> usize {
        let origin_size = limit.available();
        if let Some(response) = self.0.lock().unwrap().need_response() {
            if origin_size >= response.encoding_size() {
                buf.put_path_response_frame(&response);
            }
        }
        origin_size - buf.remaining_mut()
    }

    pub fn on_response_sent(&self, pn: u64) {
        self.0.lock().unwrap().on_response_sent(pn);
    }

    pub fn to_acked(&self) {
        self.0.lock().unwrap().acked();
    }

    pub fn may_loss_pkt(&self, pn: u64) {
        self.0.lock().unwrap().may_loss_pkt(pn);
    }

    /// Already sent path challenge response frame waiting for ack
    pub fn waiting_ack(&self) -> Option<u64> {
        self.0.lock().unwrap().waiting_ack()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_validator_challenge() {
        let mut validator = Validator::default();
        validator.set_timeout(Duration::from_millis(100));
        {
            validator.challenge();
            let state = validator.state.lock().unwrap();
            assert!(state.need_send_challenge().is_some());
        }

        {
            validator.challenge();
            {
                let state = validator.state.lock().unwrap();
                assert!(state.need_send_challenge().is_some());
            }
            validator.on_challenge_sent();
            let challenge = match *validator.state.lock().unwrap() {
                ValidateState::Challenging(challenge, _) => challenge,
                _ => panic!("unexpected state"),
            };
            validator.on_response(&PathResponseFrame::from(&challenge));
            let state = validator.state.lock().unwrap();
            assert!(matches!(*state, ValidateState::Success))
        }

        {
            validator.challenge();
            {
                let state = validator.state.lock().unwrap();
                assert!(state.need_send_challenge().is_some());
            }
            validator.on_challenge_sent();
            let challenge = match *validator.state.lock().unwrap() {
                ValidateState::Rechallenging(challenge, _) => challenge,
                _ => panic!("unexpected state"),
            };
            validator.on_response(&PathResponseFrame::from(&challenge));
            {
                let state = validator.state.lock().unwrap();
                state.need_send_challenge();
            }
            validator.on_response(&PathResponseFrame::default());
        }
    }

    #[tokio::test]
    async fn test_validator_write_challenge() {
        let validator = Validator::default();
        validator.set_timeout(Duration::from_millis(100));
        let mut buf = [0; 1024];
        let mut limit = TransportLimit::new(Some(1024), 1024, 0);
        let bytes_written = validator.write_challenge(&mut limit, &mut buf);
        assert!(bytes_written > 0);
    }

    #[tokio::test]
    async fn test_validator_on_challenge_sent() {
        let validator = Validator::default();
        validator.set_timeout(Duration::from_millis(100));
        validator.on_challenge_sent();
        let state = validator.state.lock().unwrap();
        assert!(matches!(*state, ValidateState::Challenging(_, true)));
    }

    #[tokio::test]
    async fn test_validator_timeout() {
        let validator = Validator::default();
        validator.set_timeout(Duration::from_millis(100));
        validator.on_challenge_sent();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let state = validator.state.lock().unwrap();
        println!("{:?}", state);
        assert!(matches!(*state, ValidateState::Failure));
    }

    #[tokio::test]
    #[should_panic]
    async fn test_validator_challenge_with_failure() {
        let validator = Validator::default();
        validator.on_challenge_sent();
        validator.set_timeout(Duration::from_millis(100));
        tokio::time::sleep(Duration::from_millis(150)).await;
        {
            let state = validator.state.lock().unwrap();
            assert!(matches!(*state, ValidateState::Failure));
        }
        validator.challenge();
    }

    #[tokio::test]
    async fn test_validator_timeout_with_success() {
        let validator = Validator::default();
        validator.set_timeout(Duration::from_millis(100));
        tokio::spawn({
            let mut validator = validator.clone();
            async move {
                let challenge = match *validator.state.lock().unwrap() {
                    ValidateState::Challenging(challenge, _) => challenge,
                    _ => panic!("unexpected state"),
                };
                validator.on_response(&PathResponseFrame::from(&challenge));
            }
        });

        tokio::time::sleep(Duration::from_millis(200)).await;
        let state = validator.state.lock().unwrap();
        assert!(matches!(*state, ValidateState::Success));
    }

    #[tokio::test]
    async fn test_validator_poll_state() {
        let mut validator = Validator::default();
        validator.set_timeout(Duration::from_millis(100));
        validator.challenge();
        let challenge = match *validator.state.lock().unwrap() {
            ValidateState::Challenging(challenge, _) => challenge,
            _ => panic!("unexpected state"),
        };
        validator.on_response(&PathResponseFrame::from(&challenge));
        assert!(validator.get_validate_state().await);
    }

    #[test]
    #[should_panic]
    fn test_validator_on_challenge_sent_with_success() {
        let mut validator = Validator::default();
        validator.set_timeout(Duration::from_millis(100));
        let challenge = match *validator.state.lock().unwrap() {
            ValidateState::Challenging(challenge, _) => challenge,
            _ => panic!("unexpected state"),
        };
        validator.on_response(&PathResponseFrame::from(&challenge));
        validator.on_challenge_sent();
    }

    #[tokio::test]
    async fn test_validator_may_loss() {
        let mut validator = Validator::default();
        validator.set_timeout(Duration::from_millis(100));
        validator.may_loss();
        {
            let state = validator.state.lock().unwrap();
            assert!(state.need_send_challenge().is_some());
        }
        let challenge = match *validator.state.lock().unwrap() {
            ValidateState::Challenging(challenge, _) => challenge,
            _ => panic!("unexpected state"),
        };
        validator.on_response(&PathResponseFrame::from(&challenge));
        validator.may_loss();
        validator.challenge();
        validator.may_loss();

        let state = validator.state.lock().unwrap();
        assert!(state.need_send_challenge().is_some());
    }

    #[tokio::test]
    async fn test_validator_validated() {
        let mut validator = Validator::default();
        validator.set_timeout(Duration::from_millis(100));
        validator.validated();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let state = validator.state.lock().unwrap();
        assert!(matches!(*state, ValidateState::Success));
    }

    #[tokio::test]
    async fn test_validator_on_response() {
        let mut validator = Validator::default();
        validator.set_timeout(Duration::from_millis(100));
        validator.challenge();
        let challenge = match *validator.state.lock().unwrap() {
            ValidateState::Challenging(challenge, _) => challenge,
            _ => panic!("unexpected state"),
        };
        validator.on_response(&PathResponseFrame::from(&challenge));
        let state = validator.state.lock().unwrap();
        assert!(matches!(*state, ValidateState::Success));
    }

    #[test]
    fn test_transponder_on_challenge() {
        let transponder = Transponder::default();
        let challenge = PathChallengeFrame::random();
        {
            transponder.on_challenge(challenge);
            let state = transponder.0.lock().unwrap();
            assert!(state.need_response().is_some());
        }
        {
            transponder.on_challenge(PathChallengeFrame::random());
            transponder.on_response_sent(0);
            let state = transponder.0.lock().unwrap();
            assert!(state.need_response().is_none());
        }
    }

    #[test]
    fn test_transponder_write_response() {
        let transponder = Transponder::default();
        let mut buf = [0; 1024];
        let mut limit = TransportLimit::new(Some(1024), 1024, 0);
        let bytes_written = transponder.write_response(&mut limit, &mut buf);
        assert!(bytes_written == 0);
        transponder.on_challenge(PathChallengeFrame::random());
        let mut limit = TransportLimit::new(Some(1024), 1024, 0);
        let bytes_written = transponder.write_response(&mut limit, &mut buf);
        assert!(bytes_written > 0);
    }

    #[test]
    #[should_panic]
    fn test_transponder_on_response_sent() {
        let transponder = Transponder::default();
        transponder.on_response_sent(1);
        let state = transponder.0.lock().unwrap();
        assert!(state.need_response().is_none());
    }

    #[test]
    fn test_transponder_on_pkt_acked() {
        let transponder = Transponder::default();
        transponder.to_acked();
        {
            let state = transponder.0.lock().unwrap();
            assert!(matches!(*state, ResponseState::None));
        }
        transponder.on_challenge(PathChallengeFrame::random());
        transponder.on_response_sent(1);
        transponder.to_acked();
        let state = transponder.0.lock().unwrap();
        assert!(matches!(*state, ResponseState::None));
    }

    #[test]
    fn test_transponder_may_loss_pkt() {
        let transponder = Transponder::default();
        transponder.on_challenge(PathChallengeFrame::random());
        transponder.on_response_sent(1);
        transponder.may_loss_pkt(1);
        let state = transponder.0.lock().unwrap();
        assert!(matches!(*state, ResponseState::Challenged(_, None,)));
    }
}
