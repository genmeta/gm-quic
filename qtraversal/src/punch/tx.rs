use qbase::frame::ReceiveFrame;
use tokio::sync::SetOnce;

use crate::{
    Link,
    frame::{
        TraversalFrame, collision::CollisionFrame, konck::KonckFrame, punch_done::PunchDoneFrame,
        punch_me_now::PunchMeNowFrame,
    },
};

pub(crate) struct Transaction {
    punch_me_now_frame: SetOnce<(Link, PunchMeNowFrame)>,
    collision_frame: SetOnce<(Link, CollisionFrame)>,
    konck_frame: SetOnce<(Link, KonckFrame)>,
    punch_done_frame: SetOnce<(Link, PunchDoneFrame)>,
}

impl Transaction {
    pub fn new() -> Self {
        Self {
            punch_me_now_frame: SetOnce::new(),
            collision_frame: SetOnce::new(),
            konck_frame: SetOnce::new(),
            punch_done_frame: SetOnce::new(),
        }
    }

    pub fn try_punch_done(&self) -> Option<(Link, PunchDoneFrame)> {
        self.punch_done_frame.get().cloned()
    }

    pub async fn recv_punch_done(&self) -> (Link, PunchDoneFrame) {
        *self.punch_done_frame.wait().await
    }

    pub async fn recv_konck(&self) -> (Link, KonckFrame) {
        *self.konck_frame.wait().await
    }

    pub async fn receive_punch_me_now(&self) -> PunchMeNowFrame {
        self.punch_me_now_frame.wait().await.1
    }
}

impl ReceiveFrame<(Link, TraversalFrame)> for Transaction {
    type Output = ();

    fn recv_frame(
        &self,
        (link, frame): &(Link, TraversalFrame),
    ) -> Result<Self::Output, qbase::error::Error> {
        match frame {
            TraversalFrame::Konck(konck_frame) => {
                _ = self.konck_frame.set((*link, *konck_frame));
            }
            TraversalFrame::PunchDone(punch_done_frame) => {
                _ = self.punch_done_frame.set((*link, *punch_done_frame));
            }
            TraversalFrame::Collision(collision_frame) => {
                _ = self.collision_frame.set((*link, *collision_frame));
            }
            TraversalFrame::PunchMeNow(punch_me_now_frame) => {
                _ = self.punch_me_now_frame.set((*link, *punch_me_now_frame));
            }
            frame => tracing::debug!(target: "punch", ?frame, "Recv unexpected punch frame type"),
        };
        Ok(())
    }
}
