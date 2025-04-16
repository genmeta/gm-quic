use std::{
    io,
    net::SocketAddr,
    sync::{Arc, OnceLock},
};

use dashmap::DashMap;
use qconnection::prelude::QuicInterface;
use tokio::task::{AbortHandle, JoinHandle};

pub enum Interfaces {}

impl Interfaces {
    fn interfaces() -> &'static DashMap<SocketAddr, AbortHandle> {
        static INTERFACES: OnceLock<DashMap<SocketAddr, AbortHandle>> = OnceLock::new();
        INTERFACES.get_or_init(Default::default)
    }

    pub fn add(quic_iface: Arc<dyn QuicInterface>) -> io::Result<JoinHandle<io::Result<()>>> {
        let local_addr = quic_iface.local_addr()?;
        let entry = Self::interfaces().entry(local_addr);
        if let dashmap::Entry::Occupied(..) = &entry {
            crate::proto().del_interface(local_addr);
        };
        let recv_task = crate::proto().add_interface(local_addr, quic_iface);
        entry.insert(recv_task.abort_handle());
        Ok(recv_task)
    }

    pub fn del(local_addr: SocketAddr, interface: &Arc<dyn QuicInterface>) {
        if let dashmap::Entry::Occupied(entry) = Self::interfaces().entry(local_addr) {
            let removed = crate::proto().del_interface_if(local_addr, |quic_iface, _task| {
                Arc::ptr_eq(interface, quic_iface)
            });
            if removed {
                entry.remove();
            }
        }
    }

    pub fn try_acquire_unique(local_addr: SocketAddr) -> Option<Arc<dyn QuicInterface>> {
        let _guard = Self::interfaces().get_mut(&local_addr)?;

        let iface = crate::proto()
            .get_interface(local_addr)
            .expect("unreachable, this is a bug");
        if Arc::strong_count(&iface) == 3 {
            Some(iface)
        } else {
            None
        }
    }

    pub fn try_acquire_shared(local_addr: SocketAddr) -> Option<Arc<dyn QuicInterface>> {
        let _guard = Self::interfaces().get_mut(&local_addr)?;

        let quic_iface = crate::proto()
            .get_interface(local_addr)
            .expect("unreachable, this is a bug");
        Some(quic_iface)
    }

    /// Try to free the interface that broken or not used by any path.
    ///
    /// If server or client doest want to let the interface to be freed, it could hold an interface
    /// instance to keep interfaces reference count greater than 1.
    pub fn try_free_interface(local_addr: SocketAddr) -> bool {
        match Self::interfaces().entry(local_addr) {
            // iface被remove时task也会被abort，所以不用手动
            dashmap::Entry::Occupied(entry) => {
                let removed = crate::proto().del_interface_if(local_addr, |quic_iface, task| {
                    Arc::strong_count(quic_iface) == 1 || task.is_finished()
                });
                if removed {
                    entry.remove();
                }
                removed
            }
            dashmap::Entry::Vacant(..) => false,
        }
    }
}
