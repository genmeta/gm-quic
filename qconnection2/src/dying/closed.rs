use crate::{conn, router, util::subscribe};

pub struct Connection {}

impl Connection {
    pub fn new(router_if: &router::QuicProto, cid_registry: &conn::CidRegistry) -> Self {
        use subscribe::Publish;
        for local_cid in cid_registry.local.active_cids() {
            router_if.unsubscribe(&local_cid.into());
        }
        Self {}
    }
}
