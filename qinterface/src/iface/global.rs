use std::{
    io,
    ops::Deref,
    sync::{Arc, OnceLock, Weak},
};

use dashmap::DashMap;
use derive_more::Deref;
use qbase::net::addr::{BindAddr, BindUri, RealAddr};

use crate::{
    QuicIO,
    factory::ProductQuicIO,
    iface::{InterfaceContext, QuicInterface},
};

#[derive(Deref)]
pub struct QuicInterfaces {
    #[deref]
    interfaces: DashMap<BindAddr, (InterfaceContext, Weak<QuicInterface>)>,
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
            let iface_bind_addrs =
                this.interfaces
                    .iter_mut()
                    .filter_map(|entry| match entry.key() {
                        BindAddr::Socket(BindUri::Interface(bind_addr)) => {
                            Some((bind_addr.clone(), entry))
                        }
                        _ => None,
                    });

            for (bind_addr, mut iface_ctx) in iface_bind_addrs {
                let (iface_ctx, ..) = iface_ctx.value_mut();
                let Some(socket_addr) = monitor.get(&bind_addr) else {
                    continue;
                };

                // keep if real address is ok, and task is not finished, and new address same as real addr address
                if (iface_ctx.real_addr()).is_ok_and(|read_addr| {
                    !iface_ctx.task.is_finished() && read_addr == RealAddr::Internet(socket_addr)
                }) {
                    continue;
                }

                _ = iface_ctx.rebind(bind_addr.into()).await;
            }
        }
    }

    pub fn insert(
        self: &Arc<Self>,
        bind_addr: BindAddr,
        factory: Arc<dyn ProductQuicIO>,
    ) -> io::Result<Arc<QuicInterface>> {
        match self.interfaces.entry(bind_addr.clone()) {
            dashmap::Entry::Occupied(..) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Interface already exists for {bind_addr}"),
            )),
            dashmap::Entry::Vacant(entry) => {
                let iface_ctx = InterfaceContext::new(bind_addr, factory)?;
                let borrowed_iface = Arc::new(QuicInterface::new(
                    iface_ctx.bind_addr.clone(),
                    Arc::downgrade(iface_ctx.deref()),
                    self.clone(),
                ));

                entry.insert((iface_ctx, Arc::downgrade(&borrowed_iface)));
                Ok(borrowed_iface)
            }
        }
    }

    pub fn get(&self, bind_addr: &BindAddr) -> Option<Arc<QuicInterface>> {
        self.interfaces
            .get(bind_addr)
            .and_then(|entry| entry.value().1.upgrade())
    }

    pub fn remove(&self, bind_addr: BindAddr) {
        self.interfaces.remove(&bind_addr);
    }
}
