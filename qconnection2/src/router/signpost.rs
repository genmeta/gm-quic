use std::net;

use qbase::cid;

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub struct Signpost {
    cid: cid::ConnectionId,
    peer: Option<net::SocketAddr>,
}

impl From<cid::ConnectionId> for Signpost {
    fn from(value: cid::ConnectionId) -> Self {
        Self {
            cid: value,
            peer: None,
        }
    }
}

impl From<net::SocketAddr> for Signpost {
    fn from(value: net::SocketAddr) -> Self {
        Self {
            cid: cid::ConnectionId::default(),
            peer: Some(value),
        }
    }
}
