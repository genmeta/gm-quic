mod connection_id;
pub use connection_id::*;

mod local_cid;
pub use local_cid::*;

mod remote_cid;
pub use remote_cid::*;

use crate::frame::{NewConnectionIdFrame, RetireConnectionIdFrame};

#[derive(Debug, Clone)]
pub struct Registry<ISSUED, RETIRED>
where
    ISSUED: Extend<NewConnectionIdFrame> + UniqueCid,
    RETIRED: Extend<RetireConnectionIdFrame> + Clone,
{
    pub local: ArcLocalCids<ISSUED>,
    pub remote: ArcRemoteCids<RETIRED>,
}

impl<ISSUED, RETIRED> Registry<ISSUED, RETIRED>
where
    ISSUED: Extend<NewConnectionIdFrame> + UniqueCid,
    RETIRED: Extend<RetireConnectionIdFrame> + Clone,
{
    pub fn new(
        cid_len: usize,
        issued_cids: ISSUED,
        retired_cids: RETIRED,
        remote_active_cid_limit: u64,
    ) -> Self {
        Self {
            local: ArcLocalCids::new(cid_len, issued_cids),
            remote: ArcRemoteCids::with_limit(remote_active_cid_limit, retired_cids),
        }
    }
}
