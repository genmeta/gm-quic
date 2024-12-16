pub use crate::router::*;

// static INITIAL_ROUTER: LazyLock<DashMap<Signpost, [PacketEntry; 4]>> = LazyLock::new(DashMap::new);

// #[derive(Debug, PartialEq, Eq, Hash)]
// pub struct Signpost {
//     cid: ConnectionId,
//     peer_addr: Option<SocketAddr>,
// }

// impl Signpost {
//     pub fn init_with(cid: ConnectionId, peer_addr: Option<SocketAddr>) -> Self {
//         Self { cid, peer_addr }
//     }

//     pub fn with_cid_only(cid: ConnectionId) -> Self {
//         Self::init_with(cid, None)
//     }

//     pub fn with_no_cid(peer_addr: SocketAddr) -> Self {
//         Self::init_with(ConnectionId::default(), Some(peer_addr))
//     }
// }

// impl From<ConnectionId> for Signpost {
//     fn from(cid: ConnectionId) -> Self {
//         Self::with_cid_only(cid)
//     }
// }

// impl From<SocketAddr> for Signpost {
//     fn from(peer_addr: SocketAddr) -> Self {
//         Self::with_no_cid(peer_addr)
//     }
// }
