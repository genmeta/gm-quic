use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use super::ConnectionId;
use crate::{
    error::{Error, ErrorKind},
    frame::{BeFrame, FrameType, NewConnectionIdFrame, RetireConnectionIdFrame},
    token::ResetToken,
    util::{ArcAsyncDeque, IndexDeque, IndexError},
    varint::{VarInt, VARINT_MAX},
};

/// 我方负责发放足够的cid，poll_issue_cid，将当前有效的cid注册到连接id路由。
/// 当cid不足时，就发放新的连接id，包括增大active_cid_limit，以及对方淘汰旧的cid。
#[derive(Debug, Default)]
pub struct RawLocalCids {
    // If the item in cid_deque is None, it means the connection ID has been retired.
    cid_deque: IndexDeque<Option<(ConnectionId, ResetToken)>, VARINT_MAX>,
    retired_cids: ArcAsyncDeque<ConnectionId>,
    // This is an integer value specifying the maximum number of connection
    // IDs from the peer that an endpoint is willing to store.
    // While the client does not know the server's parameters, it can be set to None.
    // If this transport parameter is absent, a default of 2 is assumed.
    active_cid_limit: Option<u64>,
    // awake the task to issue new cid
    issue_waker: Option<Waker>,
}

impl RawLocalCids {
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
        self.active_cid_limit = Some(active_cid_limit);
        if let Some(waker) = self.issue_waker.take() {
            waker.wake();
        }
        Ok(())
    }

    /// Issue a new unique connection ID with the given length.
    /// Return a new connection ID frame, which must be sent to the peer.
    fn poll_issue_cid<P>(
        &mut self,
        cx: &mut Context<'_>,
        len: usize,
        predicate: P,
    ) -> Poll<Result<NewConnectionIdFrame, IndexError>>
    where
        P: Fn(&ConnectionId) -> bool,
    {
        // If this transport parameter is absent, a default of 2 is assumed.
        let limit = self.active_cid_limit.unwrap_or(2);
        let active_len = self.cid_deque.iter().filter(|v| v.is_some()).count();
        if active_len >= limit as usize {
            self.issue_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let id = std::iter::from_fn(|| Some(ConnectionId::random_gen(len)))
            .find(predicate)
            .unwrap();
        let reset_token = ResetToken::random_gen();
        let sequence = match self.cid_deque.push_back(Some((id, reset_token))) {
            Ok(seq) => seq,
            Err(e) => return Poll::Ready(Err(e)),
        };
        // THINK: 这里可能不对，retire_prior_to..seq中间还有些已经被淘汰的cid，没计算在内
        let retire_prior_to: u64 = sequence.saturating_sub(limit);
        Poll::Ready(Ok(NewConnectionIdFrame {
            sequence: VarInt::from_u64(sequence).unwrap(),
            retire_prior_to: VarInt::from_u64(retire_prior_to).unwrap(),
            id,
            reset_token,
        }))
    }

    /// When a RetireConnectionIdFrame is acknowledged by the peer, call this method to
    /// retire the connection IDs of the sequence in RetireConnectionIdFrame.
    fn recv_retire_cid_frame(&mut self, frame: RetireConnectionIdFrame) -> Result<(), Error> {
        let seq = frame.sequence.into_inner();
        if seq >= self.cid_deque.largest() {
            return Err(Error::new(
                ErrorKind::ConnectionIdLimit,
                frame.frame_type(),
                format!(
                    "seq({seq}) in RetireConnectionIdFrame exceeds the largest one({}) issued by us",
                    self.cid_deque.largest().saturating_sub(1)
                ),
            ));
        }

        if let Some(value) = self.cid_deque.get_mut(seq) {
            if let Some((cid, _)) = value.take() {
                let active_len = self.cid_deque.iter().filter(|v| v.is_some()).count();
                if (active_len as u64) < self.active_cid_limit.unwrap_or(2) {
                    if let Some(waker) = self.issue_waker.take() {
                        waker.wake();
                    }
                }
                let n = self.cid_deque.iter().take_while(|v| v.is_none()).count();
                self.cid_deque.advance(n);
                self.retired_cids.push(cid);
            }
        }
        Ok(())
    }

    pub fn retired_cids(&self) -> ArcAsyncDeque<ConnectionId> {
        self.retired_cids.clone()
    }
}

impl Drop for RawLocalCids {
    fn drop(&mut self) {
        self.cid_deque
            .iter()
            .filter_map(|item| item.map(|(cid, _)| cid))
            .for_each(|cid| self.retired_cids.push(cid));
    }
}

#[derive(Debug, Default, Clone)]
pub struct ArcLocalCids(Arc<Mutex<RawLocalCids>>);

impl ArcLocalCids {
    pub fn set_limit(&self, active_cid_limit: u64) -> Result<(), Error> {
        self.0.lock().unwrap().set_limit(active_cid_limit)
    }

    pub fn issue_cid<P>(&self, len: usize, predicate: P) -> IssueCid<P>
    where
        P: Fn(&ConnectionId) -> bool,
    {
        IssueCid {
            local_cids: self.clone(),
            len,
            predicate,
        }
    }

    pub fn retired_cids(&self) -> ArcAsyncDeque<ConnectionId> {
        self.0.lock().unwrap().retired_cids()
    }

    pub fn recv_retire_cid_frame(&self, frame: RetireConnectionIdFrame) -> Result<(), Error> {
        self.0.lock().unwrap().recv_retire_cid_frame(frame)
    }
}

pub struct IssueCid<P> {
    local_cids: ArcLocalCids,
    len: usize,
    predicate: P,
}

impl<P> Future for IssueCid<P>
where
    P: Fn(&ConnectionId) -> bool,
{
    type Output = Result<NewConnectionIdFrame, IndexError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.local_cids.0.lock().unwrap();
        guard.poll_issue_cid(cx, self.len, &self.predicate)
    }
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll};

    use futures::task::noop_waker_ref;

    use super::*;

    #[test]
    fn test_issue_cid() {
        let local_cids = ArcLocalCids::default();
        let retired_cids = local_cids.retired_cids();
        let mut guard = local_cids.0.lock().unwrap();
        let predicate = |_: &ConnectionId| true;
        let mut cx = Context::from_waker(noop_waker_ref());

        for i in 0..2 {
            let issue_cid = guard.poll_issue_cid(&mut cx, 4, predicate);
            assert!(issue_cid.is_ready());
            if let Poll::Ready(v) = issue_cid {
                assert!(v.is_ok());
                let frame = v.unwrap();
                assert_eq!(frame.id.len, 4);
                assert_eq!(frame.sequence.into_inner(), i);
                assert_eq!(frame.retire_prior_to.into_inner(), 0);
            }
        }
        let issue_cid = guard.poll_issue_cid(&mut cx, 4, predicate);
        assert!(issue_cid.is_pending());

        guard.set_limit(3).unwrap();
        let issue_cid = guard.poll_issue_cid(&mut cx, 4, predicate);
        assert!(issue_cid.is_ready());
        assert!(retired_cids.is_empty());
    }

    #[test]
    fn test_recv_retire_cid_frame() {
        let mut local_cids = RawLocalCids::default();
        let retired_cids = local_cids.retired_cids();
        let predicate = |_: &ConnectionId| true;
        let mut cx = Context::from_waker(noop_waker_ref());

        let issued_cid1 = local_cids.poll_issue_cid(&mut cx, 4, predicate);
        let issued_cid2 = local_cids.poll_issue_cid(&mut cx, 4, predicate);
        assert!(local_cids.cid_deque.len() == 2);

        let issued_cid1 = match issued_cid1 {
            Poll::Ready(Ok(v)) => v.id,
            _ => unreachable!("unexpected"),
        };
        let issued_cid2 = match issued_cid2 {
            Poll::Ready(Ok(v)) => v.id,
            _ => unreachable!("unexpected"),
        };

        let retire_frame = RetireConnectionIdFrame {
            sequence: VarInt::from_u32(1),
        };
        let cid2 = local_cids.recv_retire_cid_frame(retire_frame);
        assert_eq!(cid2, Ok(()));
        assert_eq!(retired_cids.pop(), Some(issued_cid2));
        assert_eq!(local_cids.cid_deque.get(1), Some(&None));

        let retire_frame = RetireConnectionIdFrame {
            sequence: VarInt::from_u32(0),
        };
        let cid1 = local_cids.recv_retire_cid_frame(retire_frame);
        assert_eq!(cid1, Ok(()));
        assert_eq!(retired_cids.pop(), Some(issued_cid1));
        assert_eq!(local_cids.cid_deque.get(0), None); // have been slided out

        let retire_frame = RetireConnectionIdFrame {
            sequence: VarInt::from_u32(2),
        };
        let cid3 = local_cids.recv_retire_cid_frame(retire_frame);
        assert_eq!(
            cid3,
            Err(Error::new(
                ErrorKind::ConnectionIdLimit,
                FrameType::RetireConnectionId,
                String::from(
                    "seq(2) in RetireConnectionIdFrame exceeds the largest one(1) issued by us"
                )
            ))
        );
    }

    #[tokio::test]
    async fn test_issue_cid_async() {
        let local_cids = ArcLocalCids::default();
        tokio::spawn({
            let local_cids = local_cids.clone();
            async move {
                let predicate = |_: &ConnectionId| true;
                for i in 0..10 {
                    let issue_cid = local_cids.issue_cid(4, predicate).await.unwrap();
                    assert_eq!(issue_cid.id.len, 4);
                    assert_eq!(issue_cid.sequence.into_inner(), i);
                    assert_eq!(issue_cid.retire_prior_to.into_inner(), 0);
                }
            }
        });
        _ = local_cids.0.lock().unwrap().set_limit(10);
    }
}
