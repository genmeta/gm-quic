use std::collections::VecDeque;

use crate::quic::{
    error::Error,
    frames::{self, Frame, ResetToken},
};

use super::{cid::ConnectionIdEntry, ConnectionId};

#[derive(Default)]
struct CidQueue {
    inner: VecDeque<ConnectionIdEntry>,
    capacity: usize,
}

impl CidQueue {
    fn new(capacity: usize, initial_entry: ConnectionIdEntry) -> Self {
        let mut inner = VecDeque::with_capacity(1);
        inner.push_back(initial_entry);
        Self { inner, capacity }
    }

    fn get_oldest(&self) -> &ConnectionIdEntry {
        self.inner.front().expect("vecdeque is empty")
    }

    fn get(&self, seq: u64) -> Option<&ConnectionIdEntry> {
        self.inner.iter().find(|e| e.seq == seq)
    }

    fn get_mut(&mut self, seq: u64) -> Option<&mut ConnectionIdEntry> {
        self.inner.iter_mut().find(|e| e.seq == seq)
    }

    fn iter(&self) -> impl Iterator<Item = &ConnectionIdEntry> {
        self.inner.iter()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn resize(&mut self, new_capacity: usize) {
        if new_capacity > self.capacity {
            self.capacity = new_capacity;
        }
    }

    fn insert(&mut self, e: ConnectionIdEntry) -> Result<(), Error> {
        // Ensure we don't have duplicates.
        match self.get_mut(e.seq) {
            Some(oe) => *oe = e,
            None => {
                if self.inner.len() == self.capacity {
                    return Err(Error::IdLimit);
                }
                self.inner.push_back(e);
            }
        };
        Ok(())
    }

    fn remove(&mut self, seq: u64) -> Result<Option<ConnectionIdEntry>, Error> {
        if self.inner.len() <= 1 {
            return Err(Error::OutOfIdentifiers);
        }

        Ok(self
            .inner
            .iter()
            .position(|e| e.seq == seq)
            .and_then(|index| self.inner.remove(index)))
    }

    /// Upon receipt of an increased Retire Prior To field,
    /// the peer MUST stop using the corresponding connection IDs and
    /// retire them with RETIRE_CONNECTION_ID frames
    /// before adding the newly provided connection ID to the set of active connection IDs
    fn remove_lower_than_and_insert<F>(
        &mut self,
        seq: u64,
        e: ConnectionIdEntry,
        mut f: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&ConnectionIdEntry),
    {
        // The insert entry MUST have a sequence higher or equal to the ones
        // being retired.
        if e.seq < seq {
            return Err(Error::OutOfIdentifiers);
        }

        // To avoid exceeding the capacity of the inner `VecDeque`, we first
        // remove the elements and then insert the new one.
        self.inner.retain(|e| {
            if e.seq < seq {
                f(e);
                false
            } else {
                true
            }
        });

        // Note that if no element has been retired and the `VecDeque` reaches
        // its capacity limit, this will raise an `IdLimit`.
        self.insert(e)
    }
}

#[derive(Default)]
pub struct SourceConnectionIdentifiers {
    /// All the Source Connection IDs provided by our peer.
    cids: CidQueue,

    /// Source Connection IDs that should be announced to the peer.
    advertise_new_cid_seqs: VecDeque<u64>,

    /// Retired Source Connection IDs that should be notified to the
    /// application.
    retired_cids: VecDeque<ConnectionId>,

    /// Next sequence number to use.
    next_cid_seq: u64,

    /// "Retire Prior To" value to advertise to the peer.
    retire_prior_to: u64,

    /// The maximum number of source Connection IDs our peer allows us.
    source_conn_id_limit: usize,

    /// Does the host use zero-length source Connection ID.
    zero_length_cid: bool,
}

impl SourceConnectionIdentifiers {
    pub fn new(
        initial_scid: &ConnectionId,
        initial_path_id: usize,
        reset_token: Option<ResetToken>,
    ) -> SourceConnectionIdentifiers {
        // Initially, the limit of active source connection IDs is 2.
        let source_conn_id_limit = 2;

        // Record the zero-length SCID status.
        let zero_length_cid = initial_scid.is_empty();

        let initial_scid = initial_scid.clone();

        let cids = CidQueue::new(
            2 * source_conn_id_limit - 1,
            ConnectionIdEntry {
                cid: initial_scid,
                seq: 0,
                reset_token,
                path_id: Some(initial_path_id),
            },
        );

        let next_cid_seq = 1;
        SourceConnectionIdentifiers {
            cids,
            advertise_new_cid_seqs: VecDeque::new(),
            retired_cids: VecDeque::new(),
            next_cid_seq,
            retire_prior_to: 0,
            source_conn_id_limit,
            zero_length_cid,
        }
    }

    pub fn set_conn_id_limit(&mut self, v: u64) {
        // Bound conn id limit so our scids queue sizing is valid.
        let v = std::cmp::min(v, (usize::MAX / 2) as u64) as usize;

        // It must be at least 2.
        if v >= 2 {
            self.source_conn_id_limit = v;
            // We need to track up to (2 * source_conn_id_limit - 1) source
            // Connection IDs when the host wants to force their renewal.
            self.cids.resize(2 * v - 1);
        }
    }

    #[inline]
    pub fn get_cid(&self, seq_num: u64) -> Result<&ConnectionIdEntry, Error> {
        self.cids.get(seq_num).ok_or(Error::InvalidState)
    }

    pub fn new_cid(
        &mut self,
        cid: ConnectionId,
        reset_token: Option<ResetToken>,
        advertise: bool,
        path_id: Option<usize>,
        retire_if_needed: bool,
    ) -> Result<u64, Error> {
        if self.zero_length_cid {
            return Err(Error::InvalidState);
        }

        if self.cids.len() >= self.source_conn_id_limit {
            if !retire_if_needed {
                return Err(Error::IdLimit);
            }

            // We need to retire the lowest one.
            self.retire_prior_to = self.lowest_usable_cid_seq()? + 1;
        }

        let seq = self.next_cid_seq;

        if reset_token.is_none() && seq != 0 {
            return Err(Error::InvalidState);
        }

        // Check first that the SCID has not been inserted before.
        if let Some(e) = self.cids.iter().find(|e| e.cid == cid) {
            if e.reset_token != reset_token {
                return Err(Error::InvalidState);
            }
            return Ok(e.seq);
        }

        self.cids.insert(ConnectionIdEntry {
            cid,
            seq,
            reset_token,
            path_id,
        })?;
        self.next_cid_seq += 1;

        self.mark_advertise_new_cid_seq(seq, advertise);

        Ok(seq)
    }

    pub fn retire_cid(&mut self, seq: u64, pkt_cid: &ConnectionId) -> Result<Option<usize>, Error> {
        if seq >= self.next_cid_seq {
            return Err(Error::InvalidState);
        }

        // 不能删除当前使用的scid
        let pid = if let Some(e) = self.cids.remove(seq)? {
            if e.cid == *pkt_cid {
                return Err(Error::InvalidState);
            }

            // Notifies the application.
            self.retired_cids.push_back(e.cid);

            // Retiring this SCID may increase the retire prior to.
            let lowest_scid_seq = self.lowest_usable_cid_seq()?;
            self.retire_prior_to = lowest_scid_seq;

            e.path_id
        } else {
            None
        };

        Ok(pid)
    }

    pub fn link_scid_to_path_id(&mut self, dcid_seq: u64, path_id: usize) -> Result<(), Error> {
        let e = self.cids.get_mut(dcid_seq).ok_or(Error::InvalidState)?;
        e.path_id = Some(path_id);
        Ok(())
    }

    #[inline]
    pub fn lowest_usable_cid_seq(&self) -> Result<u64, Error> {
        self.cids
            .iter()
            .filter_map(|e| {
                if e.seq >= self.retire_prior_to {
                    Some(e.seq)
                } else {
                    None
                }
            })
            .min()
            .ok_or(Error::InvalidState)
    }

    #[inline]
    pub fn find_cid_seq(&self, scid: &ConnectionId) -> Option<(u64, Option<usize>)> {
        self.cids.iter().find_map(|e| {
            if e.cid == *scid {
                Some((e.seq, e.path_id))
            } else {
                None
            }
        })
    }

    // the path is not used
    #[inline]
    pub fn available_cids(&self) -> usize {
        self.cids.iter().filter(|e| e.path_id.is_none()).count()
    }

    #[inline]
    pub fn oldest_cid(&self) -> &ConnectionIdEntry {
        self.cids.get_oldest()
    }

    #[inline]
    pub fn mark_advertise_new_cid_seq(&mut self, scid_seq: u64, advertise: bool) {
        if advertise {
            self.advertise_new_cid_seqs.push_back(scid_seq);
        } else if let Some(index) = self
            .advertise_new_cid_seqs
            .iter()
            .position(|s| *s == scid_seq)
        {
            self.advertise_new_cid_seqs.remove(index);
        }
    }

    #[inline]
    pub fn next_advertise_new_cid_seq(&self) -> Option<u64> {
        self.advertise_new_cid_seqs.front().copied()
    }

    #[inline]
    pub fn has_new_cids(&self) -> bool {
        !self.advertise_new_cid_seqs.is_empty()
    }

    #[inline]
    pub fn zero_length_cid(&self) -> bool {
        self.zero_length_cid
    }

    // todo: 应该返回一个整体的 frame 结构
    pub fn get_new_connection_id_frame_for(
        &self,
        sequence: u64,
    ) -> Result<frames::NewConnectionId, Error> {
        let e = self.cids.get(sequence).ok_or(Error::InvalidState)?;

        Ok(frames::NewConnectionId {
            sequence,
            retire_prior_to: self.retire_prior_to,
            id: e.cid.clone(),
            reset_token: e.reset_token.ok_or(Error::InvalidState)?.clone(),
        })
    }

    #[inline]
    pub fn active_cids_len(&self) -> usize {
        self.cids.len()
    }

    pub fn pop_retired_cid(&mut self) -> Option<ConnectionId> {
        self.retired_cids.pop_front()
    }
}

pub struct DestConnectionIdentifiers {
    /// All the Destination Connection IDs provided by our peer.
    cids: CidQueue,

    /// Retired Destination Connection IDs that should be announced to the peer.
    retire_dcid_seqs: VecDeque<u64>,

    /// Largest "Retire Prior To" we received from the peer.
    largest_peer_retire_prior_to: u64,

    /// Largest sequence number we received from the peer.
    largest_destination_seq: u64,

    zero_length_dcid: bool,
}

impl DestConnectionIdentifiers {
    pub fn new(destination_conn_id_limit: usize, initial_path_id: usize) -> Self {
        let cids = CidQueue::new(
            destination_conn_id_limit,
            ConnectionIdEntry {
                cid: ConnectionId::default(),
                seq: 0,
                reset_token: None,
                path_id: Some(initial_path_id),
            },
        );
        Self {
            cids,
            retire_dcid_seqs: VecDeque::new(),
            largest_peer_retire_prior_to: 0,
            largest_destination_seq: 0,
            zero_length_dcid: false,
        }
    }

    pub fn new_dcid(
        &mut self,
        cid: ConnectionId,
        seq: u64,
        reset_token: ResetToken,
        retire_prior_to: u64,
    ) -> Result<Vec<(u64, usize)>, Error> {
        if self.zero_length_dcid {
            return Err(Error::InvalidState);
        }

        let mut retired_path_ids = Vec::new();

        if let Some(e) = self.cids.iter().find(|e| e.cid == cid || e.seq == seq) {
            if e.cid != cid || e.seq != seq || e.reset_token != Some(reset_token) {
                return Err(Error::InvalidFrame);
            }
            // The identifier is already there, nothing to do.
            return Ok(retired_path_ids);
        }

        if retire_prior_to > seq {
            return Err(Error::InvalidFrame);
        }

        if seq < self.largest_peer_retire_prior_to && !self.retire_dcid_seqs.contains(&seq) {
            self.retire_dcid_seqs.push_back(seq);
            return Ok(retired_path_ids);
        }

        if seq > self.largest_destination_seq {
            self.largest_destination_seq = seq;
        }

        let new_entry = ConnectionIdEntry {
            cid: cid.clone(),
            seq,
            reset_token: Some(reset_token),
            path_id: None,
        };

        if retire_prior_to > self.largest_peer_retire_prior_to {
            let retired = &mut self.retire_dcid_seqs;
            self.cids
                .remove_lower_than_and_insert(retire_prior_to, new_entry, |e| {
                    retired.push_back(e.seq);

                    if let Some(pid) = e.path_id {
                        retired_path_ids.push((e.seq, pid));
                    }
                })?;
            self.largest_peer_retire_prior_to = retire_prior_to;
        } else {
            self.cids.insert(new_entry)?;
        }

        Ok(retired_path_ids)
    }

    pub fn retire_cid(&mut self, seq: u64) -> Result<Option<usize>, Error> {
        if self.zero_length_dcid {
            return Err(Error::InvalidState);
        }

        let e = self.cids.remove(seq)?.ok_or(Error::InvalidState)?;

        self.retire_dcid_seqs.push_back(seq);

        Ok(e.path_id)
    }

    pub fn link_cid_to_path_id(&mut self, dcid_seq: u64, path_id: usize) -> Result<(), Error> {
        let e = self.cids.get_mut(dcid_seq).ok_or(Error::InvalidState)?;
        e.path_id = Some(path_id);
        Ok(())
    }

    #[inline]
    pub fn lowest_available_cid_seq(&self) -> Option<u64> {
        self.cids
            .iter()
            .filter_map(|e| {
                if e.path_id.is_none() {
                    Some(e.seq)
                } else {
                    None
                }
            })
            .min()
    }

    #[inline]
    pub fn mark_retire_cid_seq(&mut self, dcid_seq: u64, retire: bool) {
        if retire {
            self.retire_dcid_seqs.push_back(dcid_seq);
        } else if let Some(index) = self.retire_dcid_seqs.iter().position(|s| *s == dcid_seq) {
            self.retire_dcid_seqs.remove(index);
        }
    }

    #[inline]
    pub fn next_retire_dcid_seq(&self) -> Option<u64> {
        self.retire_dcid_seqs.front().copied()
    }

    #[inline]
    pub fn has_retire_dcids(&self) -> bool {
        !self.retire_dcid_seqs.is_empty()
    }

    #[inline]
    pub fn zero_length_dcid(&self) -> bool {
        self.zero_length_dcid
    }
}

#[cfg(test)]
mod test {
    use rand::RngCore;

    use crate::quic::cid::cid::{ConnectionIdGenerator, RandomConnectionIdGenerator};

    use super::*;
    #[test]
    fn ids_new_scids() {
        let mut generator = RandomConnectionIdGenerator::new(8);
        let scid = generator.generate_cid();

        let mut scids = SourceConnectionIdentifiers::new(&scid, 0, None);
        scids.set_conn_id_limit(3);

        assert_eq!(scids.available_cids(), 0);
        assert!(!scids.has_new_cids());
        assert_eq!(scids.next_advertise_new_cid_seq(), None);

        let mut reset_bytes = [0; 16];
        rand::thread_rng().fill_bytes(&mut reset_bytes[..16]);
        let scid2 = generator.generate_cid();
        let reset_token2 = ResetToken::new_with(&reset_bytes);
        assert_eq!(
            scids.new_cid(scid2, Some(reset_token2), true, None, false),
            Ok(1)
        );
        assert_eq!(scids.available_cids(), 1);
        assert!(scids.has_new_cids());
        assert_eq!(scids.next_advertise_new_cid_seq(), Some(1));

        // scid 3
        let mut reset_bytes = [0; 16];
        rand::thread_rng().fill_bytes(&mut reset_bytes[..16]);
        let scid3 = generator.generate_cid();
        let reset_token3 = ResetToken::new_with(&reset_bytes);

        assert_eq!(
            scids.new_cid(scid3, Some(reset_token3), true, None, false),
            Ok(2)
        );
        assert_eq!(scids.available_cids(), 2);
        assert!(scids.has_new_cids());
        assert_eq!(scids.next_advertise_new_cid_seq(), Some(1));

        // scid 4
        let mut reset_bytes = [0; 16];
        rand::thread_rng().fill_bytes(&mut reset_bytes[..16]);
        let scid4 = generator.generate_cid();
        let reset_token4 = ResetToken::new_with(&reset_bytes);
        assert_eq!(
            scids.new_cid(scid4, Some(reset_token4), true, None, false),
            Err(Error::IdLimit),
        );
        assert_eq!(scids.available_cids(), 2);
        assert!(scids.has_new_cids());
        assert_eq!(scids.next_advertise_new_cid_seq(), Some(1));

        // advertise new scid
        scids.mark_advertise_new_cid_seq(1, false);
        assert_eq!(scids.available_cids(), 2);
        assert!(scids.has_new_cids());
        assert_eq!(scids.next_advertise_new_cid_seq(), Some(2));

        scids.mark_advertise_new_cid_seq(2, false);

        assert_eq!(scids.available_cids(), 2);
        assert!(!scids.has_new_cids());
        assert_eq!(scids.next_advertise_new_cid_seq(), None);

        // retried cid
        assert_eq!(scids.retire_cid(1, &scid), Ok(None));
        assert_eq!(scids.available_cids(), 1);
        let len = scids.retired_cids.len();
        assert_eq!(len, 1);

        let ret = scids.retire_cid(2, &scid3);
        assert_eq!(ret, Err(Error::InvalidState));
        assert_eq!(scids.available_cids(), 0);
        assert_eq!(scids.retired_cids.len(), 1);
    }
}
