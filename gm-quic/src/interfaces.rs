use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    sync::{Arc, LazyLock},
};

use dashmap::DashMap;
use qconnection::prelude::QuicInterface;
use tokio::task::{AbortHandle, JoinHandle};

use crate::PROTO;

static INTERFACES: LazyLock<DashMap<SocketAddr, AbortHandle>> = LazyLock::new(Default::default);

pub(crate) enum Interfaces {}

impl Interfaces {
    pub fn add(
        quic_iface: Arc<dyn QuicInterface>,
    ) -> io::Result<JoinHandle<io::Result<Infallible>>> {
        let local_addr = quic_iface.local_addr()?;
        let entry = INTERFACES.entry(local_addr);
        if let dashmap::Entry::Occupied(..) = &entry {
            PROTO.del_interface(local_addr);
        };
        let recv_task = PROTO.add_interface(local_addr, quic_iface);
        entry.insert(recv_task.abort_handle());
        Ok(recv_task)
    }

    pub fn try_acquire_unique(local_addr: SocketAddr) -> Option<Arc<dyn QuicInterface>> {
        let _guard = INTERFACES.get_mut(&local_addr)?;

        let iface = PROTO
            .get_interface(local_addr)
            .expect("unreachable, this is a bug");
        if Arc::strong_count(&iface) == 2 {
            Some(iface)
        } else {
            None
        }
    }

    pub fn try_acquire_shared(local_addr: SocketAddr) -> Option<Arc<dyn QuicInterface>> {
        let _guard = INTERFACES.get_mut(&local_addr)?;

        let quic_iface = PROTO
            .get_interface(local_addr)
            .expect("unreachable, this is a bug");
        Some(quic_iface)
    }

    pub fn try_free_interface(local_addr: SocketAddr) -> bool {
        match INTERFACES.entry(local_addr) {
            // iface被remove时task也会被abort，所以不用手动
            dashmap::Entry::Occupied(_task) => PROTO
                .del_interface_if(local_addr, |quic_iface, task| {
                    Arc::strong_count(quic_iface) == 1 || task.is_finished()
                }),
            dashmap::Entry::Vacant(..) => false,
        }
    }
}
