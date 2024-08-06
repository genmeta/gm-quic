use std::sync::{Arc, LazyLock};

use dashmap::DashMap;
use qbase::cid::{ConnectionId, UniqueCid};

use crate::connection::ArcConnection;

/// Global Router for managing connections.
pub static ROUTER: LazyLock<ArcRouter> = LazyLock::new(|| ArcRouter(Arc::new(DashMap::new())));

#[derive(Clone, Debug)]
pub struct ArcRouter(Arc<DashMap<ConnectionId, ArcConnection>>);

impl UniqueCid for ArcRouter {
    fn is_unique_cid(&self, cid: &ConnectionId) -> bool {
        self.0.get(cid).is_none()
    }
}

impl ArcRouter {
    pub fn add_conn(&self, cid: ConnectionId, conn: ArcConnection) {
        self.0.insert(cid, conn);
    }

    pub fn remove_conn(&self, cid: ConnectionId) {
        self.0.remove(&cid);
    }
}
