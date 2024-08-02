mod connection_id;
pub use connection_id::*;

mod local_cid;
pub use local_cid::*;

mod remote_cid;
pub use remote_cid::*;

use crate::frame::NewConnectionIdFrame;

#[derive(Debug, Clone)]
pub struct Registry<T, U>
where
    T: for<'a> Extend<&'a NewConnectionIdFrame>,
    U: UniqueCid,
{
    pub local: ArcLocalCids<T, U>,
    pub remote: ArcRemoteCids,
}

impl<T, U> Registry<T, U>
where
    T: for<'a> Extend<&'a NewConnectionIdFrame>,
    U: UniqueCid,
{
    pub fn new(cid_len: usize, issued_cids: T, predicate: U, remote_active_cid_limit: u64) -> Self {
        Self {
            local: ArcLocalCids::new(cid_len, issued_cids, predicate),
            remote: ArcRemoteCids::with_limit(remote_active_cid_limit),
        }
    }
}
