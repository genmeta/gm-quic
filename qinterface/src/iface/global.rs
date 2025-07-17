use std::{
    io,
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, OnceLock, Weak},
};

use dashmap::{DashMap, Entry};
use qbase::net::addr::{BindUri, BindUriSchema, RealAddr};

use crate::{
    QuicIO,
    factory::ProductQuicIO,
    iface::{InterfaceContext, QuicInterface},
};

#[derive(Debug)]
pub struct QuicInterfaces {
    interfaces: DashMap<BindUri, (InterfaceContext, Weak<QuicInterface>)>,
}

impl QuicInterfaces {
    pub fn global() -> &'static Arc<Self> {
        static GLOBAL: OnceLock<Arc<QuicInterfaces>> = OnceLock::new();
        GLOBAL.get_or_init(QuicInterfaces::new)
    }

    pub fn new() -> Arc<Self> {
        let this = Arc::new(Self {
            interfaces: DashMap::new(),
        });

        tokio::spawn(Self::rebind_on_network_changed(Arc::downgrade(&this)));

        this
    }

    async fn rebind_on_network_changed(this: Weak<Self>) {
        let monitor = super::monitor::InterfacesMonitor::global();
        let mut changed_rx = monitor.subscribe();
        while changed_rx.changed().await.is_ok() {
            let Some(this) = this.upgrade() else {
                return;
            };
            this.interfaces
                .iter_mut()
                .filter(|entry| entry.key().scheme() == BindUriSchema::Iface)
                .for_each(|mut entry| {
                    let (bind_uri, (iface_ctx, ..)) = entry.pair_mut();
                    let Ok(socket_addr) = SocketAddr::try_from(bind_uri) else {
                        return;
                    };

                    // keep if real address is ok, and task is not finished, and new address same as real addr address
                    if (iface_ctx.real_addr()).is_ok_and(|real_addr| {
                        !iface_ctx.task.is_finished()
                            && real_addr == RealAddr::Internet(socket_addr)
                    }) {
                        return;
                    }
                    _ = iface_ctx.rebind(bind_uri.clone());
                });
        }
    }

    pub fn insert(
        self: &Arc<Self>,
        bind_uri: BindUri,
        factory: Arc<dyn ProductQuicIO>,
    ) -> io::Result<Arc<QuicInterface>> {
        match self.interfaces.entry(bind_uri.clone()) {
            dashmap::Entry::Occupied(..) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Interface already exists for {bind_uri}"),
            )),
            dashmap::Entry::Vacant(entry) => {
                let iface_ctx = InterfaceContext::new(bind_uri, factory)?;
                let iface = Arc::new(QuicInterface::new(
                    iface_ctx.bind_uri.clone(),
                    Arc::downgrade(iface_ctx.deref()),
                    self.clone(),
                ));

                entry.insert((iface_ctx, Arc::downgrade(&iface)));
                Ok(iface)
            }
        }
    }

    pub fn get(&self, bind_uri: BindUri) -> Option<Arc<QuicInterface>> {
        match self.interfaces.entry(bind_uri) {
            Entry::Occupied(entry) => match entry.get().1.upgrade() {
                Some(iface) => Some(iface),
                None => {
                    entry.remove();
                    None
                }
            },
            Entry::Vacant(..) => None,
        }
    }

    pub fn get_or_insert(
        self: &Arc<Self>,
        bind_uri: BindUri,
        factory: Arc<dyn ProductQuicIO>,
    ) -> io::Result<Arc<QuicInterface>> {
        let entry = self.interfaces.entry(bind_uri.clone());

        if let Entry::Occupied(entry) = &entry {
            if let Some(iface) = entry.get().1.upgrade() {
                return Ok(iface);
            }
        }

        let iface_ctx = InterfaceContext::new(bind_uri, factory)?;
        let iface = Arc::new(QuicInterface::new(
            iface_ctx.bind_uri.clone(),
            Arc::downgrade(iface_ctx.deref()),
            self.clone(),
        ));

        entry.insert((iface_ctx, Arc::downgrade(&iface)));
        Ok(iface)
    }

    pub fn remove(&self, bind_uri: BindUri) {
        self.interfaces.remove(&bind_uri);
    }
}

impl Drop for QuicInterface {
    fn drop(&mut self) {
        self.ifaces
            .interfaces
            .remove_if(&self.bind_uri, |_, (iface_ctx, _)| {
                Weak::ptr_eq(&Arc::downgrade(iface_ctx.deref()), &self.iface)
            });
    }
}
