use std::sync::{Arc, Mutex};

use super::{ConnectionId, UniqueCid};
use crate::{
    error::{Error, ErrorKind},
    frame::{BeFrame, FrameType, NewConnectionIdFrame, RetireConnectionIdFrame},
    token::ResetToken,
    util::{ArcAsyncDeque, IndexDeque},
    varint::{VarInt, VARINT_MAX},
};

/// 我方负责发放足够的cid，poll_issue_cid，将当前有效的cid注册到连接id路由。
/// 当cid不足时，就发放新的连接id，包括增大active_cid_limit，以及对方淘汰旧的cid。
#[derive(Debug)]
pub struct RawLocalCids<T, U>
where
    T: for<'a> Extend<&'a NewConnectionIdFrame>,
    U: UniqueCid,
{
    // If the item in cid_deque is None, it means the connection ID has been retired.
    cid_deque: IndexDeque<Option<(ConnectionId, ResetToken)>, VARINT_MAX>,
    cid_len: usize,
    uniqueness: U,
    // Each issued connection ID will be written into this issued_cids.
    issued_cids: T,
    retired_cids: ArcAsyncDeque<ConnectionId>,
    // This is an integer value specifying the maximum number of connection
    // IDs from the peer that an endpoint is willing to store.
    // While the client does not know the server's parameters, it can be set to None.
    // If this transport parameter is absent, a default of 2 is assumed.
    active_cid_limit: Option<u64>,
}

impl<T, U> RawLocalCids<T, U>
where
    T: for<'a> Extend<&'a NewConnectionIdFrame>,
    U: UniqueCid,
{
    fn new(cid_len: usize, mut issued_cids: T, predicate: U) -> Self {
        let mut cid_deque = IndexDeque::default();
        for seq in 0..2 {
            let new_cid_frame = NewConnectionIdFrame::gen(
                cid_len,
                VarInt::from_u32(seq),
                VarInt::from_u32(0),
                &predicate,
            );
            issued_cids.extend([&new_cid_frame]);
            cid_deque
                .push_back(Some((new_cid_frame.id, new_cid_frame.reset_token)))
                .unwrap();
        }
        Self {
            cid_deque,
            cid_len,
            uniqueness: predicate,
            issued_cids,
            retired_cids: ArcAsyncDeque::default(),
            active_cid_limit: None,
        }
    }

    // The value of the active_connection_id_limit parameter MUST be at least 2.
    // An endpoint that receives a value less than 2 MUST close the connection
    // with an error of type TRANSPORT_PARAMETER_ERROR.
    fn set_limit(&mut self, active_cid_limit: u64) -> Result<(), Error> {
        debug_assert!(self.active_cid_limit.is_none());
        if active_cid_limit < 2 {
            return Err(Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                format!("{} < 2", active_cid_limit),
            ));
        }
        for _ in self.cid_deque.largest()..active_cid_limit {
            self.issue_new_cid();
        }
        self.active_cid_limit = Some(active_cid_limit);
        Ok(())
    }

    fn issue_new_cid(&mut self) {
        let seq = VarInt::from_u64(self.cid_deque.largest()).unwrap();
        let retire_prior_to = VarInt::from_u64(self.cid_deque.offset()).unwrap();
        let new_cid_frame =
            NewConnectionIdFrame::gen(self.cid_len, seq, retire_prior_to, &self.uniqueness);
        self.issued_cids.extend([&new_cid_frame]);
        self.cid_deque.push_back(Some((new_cid_frame.id, new_cid_frame.reset_token)))
            .expect("it's very very hard to issue a new connection ID whose sequence excceeds VARINT_MAX");
    }

    /// When a RetireConnectionIdFrame is acknowledged by the peer, call this method to
    /// retire the connection IDs of the sequence in RetireConnectionIdFrame.
    fn recv_retire_cid_frame(&mut self, frame: &RetireConnectionIdFrame) -> Result<(), Error> {
        let seq = frame.sequence.into_inner();
        if seq >= self.cid_deque.largest() {
            return Err(Error::new(
                ErrorKind::ConnectionIdLimit,
                frame.frame_type(),
                format!(
                    "Sequence({seq}) in RetireConnectionIdFrame exceeds the largest one({}) issued by us",
                    self.cid_deque.largest().saturating_sub(1)
                ),
            ));
        }

        if let Some(value) = self.cid_deque.get_mut(seq) {
            if let Some((cid, _)) = value.take() {
                let n = self.cid_deque.iter().take_while(|v| v.is_none()).count();
                self.cid_deque.advance(n);
                self.retired_cids.push(cid);

                // generates a new connection ID while retiring an old one.
                self.issue_new_cid();
            }
        }
        Ok(())
    }

    pub fn retired_cids(&self) -> ArcAsyncDeque<ConnectionId> {
        self.retired_cids.clone()
    }
}

impl<T, U> Drop for RawLocalCids<T, U>
where
    T: for<'a> Extend<&'a NewConnectionIdFrame>,
    U: UniqueCid,
{
    fn drop(&mut self) {
        self.cid_deque
            .iter()
            .filter_map(|item| item.map(|(cid, _)| cid))
            .for_each(|cid| self.retired_cids.push(cid));
    }
}

#[derive(Debug, Clone)]
pub struct ArcLocalCids<T, U>(Arc<Mutex<RawLocalCids<T, U>>>)
where
    T: for<'a> Extend<&'a NewConnectionIdFrame>,
    U: UniqueCid;

impl<T, P> ArcLocalCids<T, P>
where
    T: for<'a> Extend<&'a NewConnectionIdFrame>,
    P: UniqueCid,
{
    pub fn new(cid_len: usize, issued_cids: T, predicate: P) -> Self {
        Self(Arc::new(Mutex::new(RawLocalCids::new(
            cid_len,
            issued_cids,
            predicate,
        ))))
    }

    pub fn active_cids(&self) -> Vec<ConnectionId> {
        self.0
            .lock()
            .unwrap()
            .cid_deque
            .iter()
            .filter_map(|v| v.map(|(cid, _)| cid))
            .collect()
    }

    pub fn set_limit(&self, active_cid_limit: u64) -> Result<(), Error> {
        self.0.lock().unwrap().set_limit(active_cid_limit)
    }

    pub fn retired_cids(&self) -> ArcAsyncDeque<ConnectionId> {
        self.0.lock().unwrap().retired_cids()
    }

    pub fn recv_retire_cid_frame(&self, frame: &RetireConnectionIdFrame) -> Result<(), Error> {
        self.0.lock().unwrap().recv_retire_cid_frame(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::AlwaysUnique;

    #[test]
    fn test_issue_cid() {
        let local_cids = ArcLocalCids::new(8, Vec::new(), AlwaysUnique);
        let mut guard = local_cids.0.lock().unwrap();

        assert_eq!(guard.cid_deque.len(), 2);

        guard.set_limit(3).unwrap();
        assert_eq!(guard.cid_deque.len(), 3);
    }

    #[test]
    fn test_recv_retire_cid_frame() {
        let mut local_cids = RawLocalCids::new(8, Vec::new(), AlwaysUnique);
        let retired_cids = local_cids.retired_cids();

        assert_eq!(local_cids.cid_deque.len(), 2);
        assert_eq!(local_cids.issued_cids.len(), 2);

        let issued_cid1 = local_cids.issued_cids[0].id;
        let issued_cid2 = local_cids.issued_cids[1].id;

        let retire_frame = RetireConnectionIdFrame {
            sequence: VarInt::from_u32(1),
        };
        let cid2 = local_cids.recv_retire_cid_frame(&retire_frame);
        assert!(cid2.is_ok());
        assert_eq!(retired_cids.pop(), Some(issued_cid2));
        assert_eq!(local_cids.cid_deque.get(1), Some(&None));
        // issued new cid while retiring an old one
        assert_eq!(local_cids.cid_deque.len(), 3);
        assert_eq!(local_cids.issued_cids.len(), 3);

        let retire_frame = RetireConnectionIdFrame {
            sequence: VarInt::from_u32(0),
        };
        let cid1 = local_cids.recv_retire_cid_frame(&retire_frame);
        assert!(cid1.is_ok());
        assert_eq!(retired_cids.pop(), Some(issued_cid1));
        assert_eq!(local_cids.cid_deque.get(0), None); // have been slided out

        assert_eq!(local_cids.cid_deque.len(), 2);
        assert_eq!(local_cids.issued_cids.len(), 4);

        let retire_frame = RetireConnectionIdFrame {
            sequence: VarInt::from_u32(2),
        };
        let cid3 = local_cids.recv_retire_cid_frame(&retire_frame);
        assert!(cid3.is_ok());
    }
}
