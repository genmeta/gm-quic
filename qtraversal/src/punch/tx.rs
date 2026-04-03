use std::fmt;

use qbase::frame::{
    AddAddressFrame, PunchKnockFrame, PunchMeNowFrame, ReceiveFrame, TraversalFrame,
};
use tokio::sync::SetOnce;

use crate::Link;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PunchId {
    pub local_seq: u32,
    pub remote_seq: u32,
}

impl PunchId {
    pub fn new(local_seq: u32, remote_seq: u32) -> Self {
        Self {
            local_seq,
            remote_seq,
        }
    }

    pub fn flip(self) -> Self {
        Self {
            local_seq: self.remote_seq,
            remote_seq: self.local_seq,
        }
    }
}

impl fmt::Display for PunchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.local_seq, self.remote_seq)
    }
}

pub(crate) trait AsPunchId {
    fn punch_id(&self) -> PunchId;
}

impl AsPunchId for PunchKnockFrame {
    fn punch_id(&self) -> PunchId {
        PunchId::new(self.local_seq(), self.remote_seq())
    }
}

impl AsPunchId for PunchMeNowFrame {
    fn punch_id(&self) -> PunchId {
        PunchId::new(self.local_seq(), self.remote_seq())
    }
}

impl AsPunchId for (&AddAddressFrame, &AddAddressFrame) {
    fn punch_id(&self) -> PunchId {
        PunchId::new(self.0.seq_num(), self.1.seq_num())
    }
}

pub(crate) struct Transaction {
    punch_me_now_frame: SetOnce<PunchMeNowFrame>,
    konck_frame: SetOnce<(Link, PunchKnockFrame)>,
    punch_done_frame: SetOnce<(Link, PunchKnockFrame)>,
}

impl Transaction {
    pub fn new() -> Self {
        Self {
            punch_me_now_frame: SetOnce::new(),
            konck_frame: SetOnce::new(),
            punch_done_frame: SetOnce::new(),
        }
    }

    pub async fn recv_punch_done(&self) -> (Link, PunchKnockFrame) {
        *self.punch_done_frame.wait().await
    }

    pub async fn recv_konck(&self) -> (Link, PunchKnockFrame) {
        *self.konck_frame.wait().await
    }

    pub async fn receive_punch_me_now(&self) -> PunchMeNowFrame {
        *self.punch_me_now_frame.wait().await
    }

    pub fn set_punch_me_now(&self, frame: PunchMeNowFrame) {
        _ = self.punch_me_now_frame.set(frame);
    }
}

impl ReceiveFrame<(Link, TraversalFrame)> for Transaction {
    type Output = ();

    fn recv_frame(
        &self,
        (link, frame): &(Link, TraversalFrame),
    ) -> Result<Self::Output, qbase::error::Error> {
        match frame {
            TraversalFrame::PunchKnock(knock_frame) if !knock_frame.is_done() => {
                _ = self.konck_frame.set((*link, *knock_frame));
            }
            TraversalFrame::PunchKnock(punch_done_frame) => {
                _ = self.punch_done_frame.set((*link, *punch_done_frame));
            }
            TraversalFrame::PunchMeNow(punch_me_now_frame) => {
                _ = self.punch_me_now_frame.set(*punch_me_now_frame);
            }
            frame => tracing::debug!(target: "punch", ?frame, "Recv unexpected punch frame type"),
        };
        Ok(())
    }
}
