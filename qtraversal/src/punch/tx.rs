use std::ops::Deref;

use qbase::frame::ReceiveFrame;

use crate::{
    Link,
    frame::{
        TraversalFrame, collision::CollisionFrame, konck::KonckFrame, punch_done::PunchDoneFrame,
        punch_me_now::PunchMeNowFrame,
    },
    future::Future,
};

pub(crate) struct Transaction {
    punch_me_now_frame: Future<(Link, PunchMeNowFrame)>,
    collision_frame: Future<(Link, CollisionFrame)>,
    konck_frame: Future<(Link, KonckFrame)>,
    punch_done_frame: Future<(Link, PunchDoneFrame)>,
}

impl Transaction {
    pub fn new() -> Self {
        Self {
            punch_me_now_frame: Future::new(),
            collision_frame: Future::new(),
            konck_frame: Future::new(),
            punch_done_frame: Future::new(),
        }
    }

    pub fn try_punch_done(&self) -> Option<(Link, PunchDoneFrame)> {
        self.punch_done_frame.try_get().map(|f| *f.deref())
    }

    pub async fn recv_punch_done(&self) -> (Link, PunchDoneFrame) {
        *self.punch_done_frame.get().await
    }

    pub async fn recv_konck(&self) -> (Link, KonckFrame) {
        *self.konck_frame.get().await
    }

    pub async fn receive_punch_me_now(&self) -> PunchMeNowFrame {
        self.punch_me_now_frame.get().await.1
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
                self.konck_frame.assign((*link, *konck_frame));
            }
            TraversalFrame::PunchDone(punch_done_frame) => {
                self.punch_done_frame.assign((*link, *punch_done_frame));
            }
            TraversalFrame::Collision(collision_frame) => {
                self.collision_frame.assign((*link, *collision_frame));
            }
            TraversalFrame::PunchMeNow(punch_me_now_frame) => {
                self.punch_me_now_frame.assign((*link, *punch_me_now_frame));
            }
            frame => tracing::debug!(target: "punch", ?frame, "Recv unexpected punch frame type"),
        };
        Ok(())
    }
}
