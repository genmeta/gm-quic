use qbase::frame::{
    PunchDoneFrame, PunchKnockFrame, PunchMeNowFrame, ReceiveFrame, TraversalFrame,
};
use tokio::sync::SetOnce;

use crate::Link;

pub(crate) struct Transaction {
    punch_me_now_frame: SetOnce<PunchMeNowFrame>,
    konck_frame: SetOnce<(Link, PunchKnockFrame)>,
    punch_done_frame: SetOnce<(Link, PunchDoneFrame)>,
}

impl Transaction {
    pub fn new() -> Self {
        Self {
            punch_me_now_frame: SetOnce::new(),
            konck_frame: SetOnce::new(),
            punch_done_frame: SetOnce::new(),
        }
    }

    pub async fn recv_punch_done(&self) -> (Link, PunchDoneFrame) {
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
            TraversalFrame::PunchKnock(konck_frame) => {
                _ = self.konck_frame.set((*link, *konck_frame));
            }
            TraversalFrame::PunchDone(punch_done_frame) => {
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
