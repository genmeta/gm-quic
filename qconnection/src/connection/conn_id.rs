use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use qbase::{
    cid::ConnectionId,
    error::{Error, ErrorKind::ProtocolViolation},
    frame::{FrameType::Padding, NewConnectionIdFrame, RetireConnectionIdFrame},
    token::ResetToken,
};

#[derive(Default, Debug, Clone)]
struct EndpointConnIDs {
    deque: VecDeque<(ConnectionId, ResetToken)>,
    offset: u64,
}

impl EndpointConnIDs {
    fn all_conn_ids(&self) -> u64 {
        self.offset + self.deque.len() as u64
    }

    fn retire_to(&mut self, n: u64) {
        self.deque.drain(..(n - self.offset) as usize);
    }
}

#[derive(Default, Debug, Clone)]
pub struct ConnIDs {
    local: EndpointConnIDs,
    remote: EndpointConnIDs,
}

impl ConnIDs {
    fn new() -> Self {
        Self::default()
    }

    pub fn recv_retire_conn_id(&mut self, frame: RetireConnectionIdFrame) -> Result<(), Error> {
        // The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer
        // to the Destination Connection ID field of the packet in which the frame is
        // contained. The peer MAY treat this as a connection error of type PROTOCOL_VIOLATION.

        if frame.sequence.into_inner() > self.local.all_conn_ids() {
            return Err(Error::new(
                ProtocolViolation,
                Padding,
                "sequence number MUST NOT greater than any previously received",
            ));
        }

        self.local.retire_to(frame.sequence.into_inner());

        Ok(())
    }

    pub fn recv_new_conn_id(&mut self, frame: NewConnectionIdFrame) -> Result<(), Error> {
        if frame.retire_prior_to == frame.sequence {
            return Ok(());
        }

        if frame.retire_prior_to > frame.sequence {
            return Err(Error::new(
                ProtocolViolation,
                Padding,
                "sequence number MUST NOT be less than the retire_prior_to field",
            ));
        }

        todo!()
    }
}

#[derive(Default, Debug, Clone)]
pub struct ArcConnIDs(Arc<Mutex<ConnIDs>>);

impl ArcConnIDs {
    pub fn new() -> Self {
        Self::default()
    }
}
