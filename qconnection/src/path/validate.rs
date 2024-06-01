use qbase::frame::{PathChallengeFrame, PathResponseFrame};
use qcongestion::congestion::Epoch;

/// 路径验证器，用于验证路径的有效性。
#[derive(Debug)]
pub enum ValidateState {
    // 已发送挑战，等待响应，发送的挑战记录在哪个Epoch的哪个包号里，方便确认
    // 此时，依然收抗放大攻击的流量限制
    Challenging(PathChallengeFrame, Option<(Epoch, u64)>),
    // 再次发起挑战，此时曾经已经挑战过，与Challenging不同，不受抗放大攻击影响
    Rechallenging(PathChallengeFrame, Option<(Epoch, u64)>),
    // 当收到PathResponse帧，且内容对的上，就认为验证通过
    Success,
    // 当一段时间内，没有收到PathResponse帧，就认为验证失败
    Failure,
}

impl Default for ValidateState {
    fn default() -> Self {
        Self::Challenging(PathChallengeFrame::random(), None)
    }
}

impl ValidateState {
    pub fn challenge(&mut self) {
        match self {
            ValidateState::Challenging(_, _) | ValidateState::Rechallenging(_, _) => {
                return;
            }
            ValidateState::Success => {
                *self = ValidateState::Rechallenging(PathChallengeFrame::random(), None);
            }
            ValidateState::Failure => unreachable!("need not challenge again"),
        }
    }

    pub fn need_send_challenge(&self) -> Option<&PathChallengeFrame> {
        match self {
            ValidateState::Challenging(challenge, None) => Some(challenge),
            ValidateState::Rechallenging(challenge, None) => Some(challenge),
            _ => None,
        }
    }

    /// 必须在need_send_challenge之后调用，且确实发送了PathChallengeFrame，才可调用
    pub fn on_challenge_sent(&mut self, space: Epoch, pn: u64) {
        match self {
            ValidateState::Challenging(_, pkt) => {
                *pkt = Some((space, pn));
            }
            ValidateState::Rechallenging(_, pkt) => {
                *pkt = Some((space, pn));
            }
            _ => unreachable!("no reason to send challenge frame"),
        }
    }

    /// 曾经发送PathChallengeFrame的数据包可能丢了，需要改变状态，触发重传
    pub fn may_loss(&mut self) {
        match self {
            ValidateState::Challenging(_, pkt) => {
                *pkt = None;
            }
            ValidateState::Rechallenging(_, pkt) => {
                *pkt = None;
            }
            _ => (),
        }
    }

    pub fn on_response(&mut self, response: &PathResponseFrame) {
        match self {
            ValidateState::Challenging(challenge, _) => {
                if challenge.data == response.data {
                    *self = ValidateState::Success;
                }
            }
            ValidateState::Rechallenging(challenge, _) => {
                if challenge.data == response.data {
                    *self = ValidateState::Success;
                }
            }
            _ => (),
        }
    }
}

#[derive(Debug, Default)]
pub enum ResponseState {
    #[default]
    None,
    // 收到路径挑战帧，如果上个挑战没完成就来了新的挑战，意味着旧挑战
    // 作废，则更新挑战，后续只处理新挑战
    // 响应挑战，响应帧在哪个包号里（只可能在1RTT数据包中），用于防丢
    // 如果丢包重传，包号要更新
    Challenged(PathChallengeFrame, Option<u64>),
}

impl ResponseState {
    pub fn on_challenge(&mut self, challenge: PathChallengeFrame) {
        match self {
            ResponseState::None => {
                *self = ResponseState::Challenged(challenge, None);
            }
            ResponseState::Challenged(old_challenge, pkt) => {
                if old_challenge.data != challenge.data {
                    *old_challenge = challenge;
                    *pkt = None;
                }
            }
        }
    }

    pub fn need_response(&self) -> Option<PathResponseFrame> {
        match self {
            ResponseState::Challenged(challenge, None) => Some(challenge.response()),
            _ => None,
        }
    }

    pub fn on_responsed(&mut self, pn: u64) {
        match self {
            ResponseState::Challenged(_, pkt) => {
                assert_eq!(*pkt, None);
                *pkt = Some(pn);
            }
            _ => unreachable!("would not send path response frame"),
        }
    }

    pub fn on_pkt_acked(&mut self, pn: u64) {
        match self {
            ResponseState::Challenged(_, pkt) => {
                if *pkt == Some(pn) {
                    *self = ResponseState::None;
                }
            }
            _ => (),
        }
    }

    pub fn may_loss_pkt(&mut self, pn: u64) {
        match self {
            ResponseState::Challenged(_, pkt) => {
                if *pkt == Some(pn) {
                    *pkt = None;
                }
            }
            _ => (),
        }
    }
}
