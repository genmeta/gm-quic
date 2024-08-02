use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use qbase::cid::{ConnectionId, UniqueCid};

use crate::connection::ArcConnection;

#[derive(Clone, Debug)]
pub struct ArcRouter(Arc<Mutex<DashMap<ConnectionId, ArcConnection>>>);

impl UniqueCid for ArcRouter {
    fn is_unique_cid(&self, cid: &ConnectionId) -> bool {
        self.0.lock().unwrap().get(cid).is_none()
    }
}
