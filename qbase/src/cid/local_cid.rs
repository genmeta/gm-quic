use std::sync::{Arc, Mutex};

use super::{ConnectionId, GenUniqueCid};
use crate::{
    error::{Error, ErrorKind},
    frame::{
        BeFrame, FrameType, NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame,
    },
    token::ResetToken,
    util::IndexDeque,
    varint::{VarInt, VARINT_MAX},
};

/// Local connection ID management.
#[derive(Debug)]
struct LocalCids<ISSUED>
where
    ISSUED: GenUniqueCid + SendFrame<NewConnectionIdFrame>,
{
    // If the item in cid_deque is None, it means the connection ID has been retired.
    cid_deque: IndexDeque<Option<(ConnectionId, ResetToken)>, VARINT_MAX>,
    // Each issued connection ID will be written into this issued_cids.
    // The frames in issued_cids should be able to enter the QUIC sending channel
    // and be reliably sent to the peer finally.
    issued_cids: ISSUED,
    // This is an integer value specifying the maximum number of active connection
    // IDs limited by peer.
    // While the client does not know the server's parameters at the beginning,
    // it can be set to None and will be reset.
    // If this transport parameter is absent, a default of 2 is assumed.
    active_cid_limit: Option<u64>,
}

impl<ISSUED> LocalCids<ISSUED>
where
    ISSUED: GenUniqueCid + SendFrame<NewConnectionIdFrame>,
{
    /// Create a new local connection ID manager.
    fn new(scid: ConnectionId, issued_cids: ISSUED) -> Self {
        let mut cid_deque = IndexDeque::default();
        cid_deque
            .push_back(Some((scid, ResetToken::default())))
            .unwrap();

        let new_cid = issued_cids.gen_unique_cid();
        let new_cid_frame =
            NewConnectionIdFrame::new(new_cid, VarInt::from_u32(1), VarInt::from_u32(0));
        issued_cids.send_frame([new_cid_frame]);
        cid_deque
            .push_back(Some((new_cid_frame.id, new_cid_frame.reset_token)))
            .unwrap();
        Self {
            cid_deque,
            issued_cids,
            active_cid_limit: None,
        }
    }

    fn initial_scid(&self) -> Option<ConnectionId> {
        self.cid_deque.get(0)?.map(|(cid, _)| cid)
    }

    /// Set the maximum number of active connection IDs.
    ///
    /// The value of the active_connection_id_limit parameter MUST be at least 2.
    /// An endpoint that receives a value less than 2 MUST close the connection
    /// with an error of type TRANSPORT_PARAMETER_ERROR.
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

    /// Issue a new connection ID, for internal used only.
    fn issue_new_cid(&mut self) {
        let seq = VarInt::from_u64(self.cid_deque.largest()).unwrap();
        let retire_prior_to = VarInt::from_u64(self.cid_deque.offset()).unwrap();
        let new_cid = self.issued_cids.gen_unique_cid();
        let new_cid_frame = NewConnectionIdFrame::new(new_cid, seq, retire_prior_to);
        self.issued_cids.send_frame([new_cid_frame]);
        self.cid_deque.push_back(Some((new_cid_frame.id, new_cid_frame.reset_token)))
            .expect("it's very very hard to issue a new connection ID whose sequence excceeds VARINT_MAX");
    }

    /// Receive a [`RetireConnectionIdFrame`] from the peer,
    /// retire the connection IDs of the sequence in [`RetireConnectionIdFrame`].
    fn recv_retire_cid_frame(
        &mut self,
        frame: &RetireConnectionIdFrame,
    ) -> Result<Option<ConnectionId>, Error> {
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

                // generates a new connection ID while retiring an old one.
                self.issue_new_cid();
                return Ok(Some(cid));
            }
        }
        Ok(None)
    }
}

/// Shared local connection ID manager. Most times, you should use this struct.
///
/// Responsible for generating and issuing connection IDs to the peer.
/// The number of active connection IDs is limited by the peer's active_cid_limit.
///
/// - `ISSUED`: is a struct that can generate unique connection id and finally send the new
///    issued connection ID frame to the peer.
///    It can be a channel, a queue, or a buffer. Whatever, it must be able to send the
///    [`NewConnectionIdFrame`] to the peer.
///
/// ## Note
///
/// The generated connection ID will be added to the packet reception routing table,
/// which is shared with other QUIC connections.
/// Therefore, the generated connection ID must not duplicate other local connection IDs,
/// including connection IDs of other connections,
/// and those issued to the peer and have not been retired,
/// otherwise routing conflicts will occur.
#[derive(Debug, Clone)]
pub struct ArcLocalCids<ISSUED>(Arc<Mutex<LocalCids<ISSUED>>>)
where
    ISSUED: GenUniqueCid + SendFrame<NewConnectionIdFrame>;

impl<ISSUED> ArcLocalCids<ISSUED>
where
    ISSUED: GenUniqueCid + SendFrame<NewConnectionIdFrame>,
{
    /// Create a new share local connection ID manager.
    ///
    /// - `scid` is set initially, whether it is a client or a server,
    ///    they both get their early `scid` externally.
    /// - `issued_cids` is responsible for generating CIDs that do not conflict
    ///    in the packet reception routing table and will also be responsible for
    ///    eventually sending the [`NewConnectionIdFrame`] to the peer.
    pub fn new(scid: ConnectionId, issued_cids: ISSUED) -> Self {
        let raw_local_cids = LocalCids::new(scid, issued_cids);
        Self(Arc::new(Mutex::new(raw_local_cids)))
    }

    /// Get the initial source connection ID.
    ///
    /// 0-RTT packets in the first flight use the same Destination Connection ID
    /// and Source Connection ID values as the client's first Initial packet.
    /// see [Section 7.2.6](https://datatracker.ietf.org/doc/html/rfc9000#section-7.2-6)
    /// of [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000).
    ///
    /// Once a client has received a valid Initial packet from the server,
    /// it MUST discard any subsequent packet it receives on that connection
    /// with a different Source Connection ID,
    /// see [Section 7.2.7](https://datatracker.ietf.org/doc/html/rfc9000#section-7.2-7)
    /// of [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000).
    ///
    /// Any further changes to the Destination Connection ID are only permitted
    /// if the values are taken from NEW_CONNECTION_ID frames;
    /// if subsequent Initial packets include a different Source Connection ID,
    /// they MUST be discarded,
    /// see [Section 7.2.8](https://datatracker.ietf.org/doc/html/rfc9000#section-7.2-8)
    /// of [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000) for more details.
    ///
    /// It means that the initial source connection ID is the only one that can be used
    /// to send the Initial, 0Rtt and handshake packets.
    /// Changing the scid is like issuing a new connection ID to the other party,
    /// without specifying a sequence number or Stateless Reset Token.
    /// Changing the scid during the Handshake phase is meaningless and harmful.
    ///
    /// For the server, even though the server provides the preferred address
    /// as the first connection ID, and even though the server can use this
    /// connection ID as the scid in the Handshake packet, it is not necessary.
    /// The client does not eliminate the zero connection ID.
    /// When the client actually eliminates the zero connection ID,
    /// it means that 1RTT packets have already started to be transmitted,
    /// and all subsequent transmissions should be through 1RTT packets.
    ///
    /// Return None if the initial source connection ID has been retired,
    /// which indicates that the connection has been established,
    /// and only the short header packet should be used.
    pub fn initial_scid(&self) -> Option<ConnectionId> {
        self.0.lock().unwrap().initial_scid()
    }

    /// Get all active connection IDs.
    ///
    /// This method will be useful when finally releasing connection resources,
    /// as it will remove all routing table entries related to this connection.
    pub fn active_cids(&self) -> Vec<ConnectionId> {
        self.0
            .lock()
            .unwrap()
            .cid_deque
            .iter()
            .filter_map(|v| v.map(|(cid, _)| cid))
            .collect()
    }

    /// Set the maximum number of active connection IDs.
    ///
    /// After fully obtaining the peer's connection parameters, extract the peer's
    /// active_cid_limit parameter and set it through this method.
    pub fn set_limit(&self, active_cid_limit: u64) -> Result<(), Error> {
        self.0.lock().unwrap().set_limit(active_cid_limit)
    }
}

impl<ISSUED> ReceiveFrame<RetireConnectionIdFrame> for ArcLocalCids<ISSUED>
where
    ISSUED: GenUniqueCid + SendFrame<NewConnectionIdFrame>,
{
    type Output = Option<ConnectionId>;

    /// Receive a [`RetireConnectionIdFrame`] from the peer,
    /// retire the connection IDs of the sequence in [`RetireConnectionIdFrame`].
    fn recv_frame(
        &self,
        frame: &RetireConnectionIdFrame,
    ) -> Result<Self::Output, crate::error::Error> {
        self.0.lock().unwrap().recv_retire_cid_frame(frame)
    }
}

#[cfg(test)]
mod tests {
    use deref_derive::Deref;

    use super::*;

    #[derive(Debug, Deref, Default)]
    struct IssuedCids(Arc<Mutex<Vec<NewConnectionIdFrame>>>);

    impl IssuedCids {
        fn lock_guard(&self) -> std::sync::MutexGuard<'_, Vec<NewConnectionIdFrame>> {
            self.0.lock().unwrap()
        }
    }

    impl GenUniqueCid for IssuedCids {
        fn gen_unique_cid(&self) -> ConnectionId {
            ConnectionId::random_gen_with_mark(8, 0x80, 0x7F)
        }
    }

    impl SendFrame<NewConnectionIdFrame> for IssuedCids {
        fn send_frame<I: IntoIterator<Item = NewConnectionIdFrame>>(&self, iter: I) {
            self.0.lock().unwrap().extend(iter);
        }
    }

    #[test]
    fn test_issue_cid() {
        let initial_scid = ConnectionId::random_gen(8);
        let local_cids = ArcLocalCids::new(initial_scid, IssuedCids::default());
        let mut guard = local_cids.0.lock().unwrap();

        assert_eq!(guard.cid_deque.len(), 2);

        guard.set_limit(3).unwrap();
        assert_eq!(guard.cid_deque.len(), 3);
    }

    #[test]
    fn test_recv_retire_cid_frame() {
        let initial_scid = ConnectionId::random_gen(8);
        let mut local_cids = LocalCids::new(initial_scid, IssuedCids::default());

        assert_eq!(local_cids.cid_deque.len(), 2);
        assert_eq!(local_cids.issued_cids.lock_guard().len(), 1);

        let issued_cid2 = local_cids.issued_cids.lock_guard()[0].id;

        let retire_frame = RetireConnectionIdFrame {
            sequence: VarInt::from_u32(1),
        };
        let cid2 = local_cids.recv_retire_cid_frame(&retire_frame);
        assert!(cid2.is_ok());
        assert_eq!(cid2, Ok(Some(issued_cid2)));
        assert_eq!(local_cids.cid_deque.get(1), Some(&None));
        // issued new cid while retiring an old one
        assert_eq!(local_cids.cid_deque.len(), 3);
        assert_eq!(local_cids.issued_cids.lock_guard().len(), 2);

        let retire_frame = RetireConnectionIdFrame {
            sequence: VarInt::from_u32(0),
        };
        let cid1 = local_cids.recv_retire_cid_frame(&retire_frame);
        assert!(cid1.is_ok());
        assert_eq!(cid1, Ok(Some(initial_scid)));
        assert_eq!(local_cids.cid_deque.get(0), None); // have been slided out

        assert_eq!(local_cids.cid_deque.len(), 2);
        assert_eq!(local_cids.issued_cids.lock_guard().len(), 3);

        let retire_frame = RetireConnectionIdFrame {
            sequence: VarInt::from_u32(2),
        };
        let cid3 = local_cids.recv_retire_cid_frame(&retire_frame);
        assert!(cid3.is_ok());
    }
}
