use std::{collections::VecDeque, fmt, sync::Mutex};

use qbase::frame::{
    AddAddressFrame, PunchDoneFrame, PunchHelloFrame, PunchMeNowFrame, ReceiveFrame,
};
use tokio::sync::{Notify, SetOnce};

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

impl AsPunchId for PunchHelloFrame {
    fn punch_id(&self) -> PunchId {
        PunchId::new(self.local_seq(), self.remote_seq())
    }
}

impl AsPunchId for PunchDoneFrame {
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
    punch_hello_frame: SetOnce<(Link, PunchHelloFrame)>,
    punch_done_queue: Mutex<VecDeque<(Link, PunchDoneFrame)>>,
    punch_done_notify: Notify,
}

impl Transaction {
    pub fn new() -> Self {
        Self {
            punch_me_now_frame: SetOnce::new(),
            punch_hello_frame: SetOnce::new(),
            punch_done_queue: Mutex::new(VecDeque::new()),
            punch_done_notify: Notify::new(),
        }
    }

    pub async fn next_punch_done(&self) -> (Link, PunchDoneFrame) {
        loop {
            let notified = self.punch_done_notify.notified();
            if let Some(frame) = self.try_next_punch_done() {
                return frame;
            }
            notified.await;
        }
    }

    pub fn try_next_punch_done(&self) -> Option<(Link, PunchDoneFrame)> {
        self.punch_done_queue.lock().unwrap().pop_front()
    }

    pub async fn wait_punch_hello(&self) -> (Link, PunchHelloFrame) {
        *self.punch_hello_frame.wait().await
    }

    pub async fn wait_punch_me_now(&self) -> PunchMeNowFrame {
        *self.punch_me_now_frame.wait().await
    }

    pub fn store_punch_me_now(&self, frame: PunchMeNowFrame) {
        _ = self.punch_me_now_frame.set(frame);
    }
}

impl ReceiveFrame<(Link, PunchHelloFrame)> for Transaction {
    type Output = ();

    fn recv_frame(
        &self,
        (link, frame): &(Link, PunchHelloFrame),
    ) -> Result<Self::Output, qbase::error::Error> {
        _ = self.punch_hello_frame.set((*link, *frame));
        Ok(())
    }
}

impl ReceiveFrame<(Link, PunchDoneFrame)> for Transaction {
    type Output = ();

    fn recv_frame(
        &self,
        (link, frame): &(Link, PunchDoneFrame),
    ) -> Result<Self::Output, qbase::error::Error> {
        self.punch_done_queue
            .lock()
            .unwrap()
            .push_back((*link, *frame));
        self.punch_done_notify.notify_one();
        Ok(())
    }
}

impl ReceiveFrame<(Link, PunchMeNowFrame)> for Transaction {
    type Output = ();

    fn recv_frame(
        &self,
        (_link, frame): &(Link, PunchMeNowFrame),
    ) -> Result<Self::Output, qbase::error::Error> {
        _ = self.punch_me_now_frame.set(*frame);
        Ok(())
    }
}
