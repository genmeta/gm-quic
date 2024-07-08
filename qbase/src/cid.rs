mod connection_id;
pub use connection_id::*;

mod local_cid;
pub use local_cid::*;

mod remote_cid;
pub use remote_cid::*;

#[derive(Debug, Clone)]
pub struct Registry {
    pub local: ArcLocalCids,
    pub remote: ArcRemoteCids,
}

impl Registry {
    #[inline]
    pub fn new(remote_active_cid_limit: u64) -> Self {
        Self {
            local: ArcLocalCids::default(),
            remote: ArcRemoteCids::with_limit(remote_active_cid_limit),
        }
    }
}
