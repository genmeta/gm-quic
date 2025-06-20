pub mod monitor;
// handy（qudp）是可选的
pub mod borrowed;
pub mod handy;

use std::{
    io,
    sync::{Arc, OnceLock, Weak},
};

use dashmap::DashMap;
use qbase::net::address::{BindAddr, RealAddr, SocketBindAddr};
use tokio::task::JoinHandle;

use crate::{
    QuicInterface,
    factory::ProductQuicInterface,
    ifaces::borrowed::{BorrowedInterface, RwInterface},
    route::Router,
};

pub struct QuicInterfaces {
    interfaces: DashMap<BindAddr, (InterfaceContext, Weak<BorrowedInterface>)>,
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
        let monitor = monitor::InterfacesMonitor::global();
        let mut changed_rx = monitor.subscribe();
        while changed_rx.changed().await.is_ok() {
            let Some(this) = this.upgrade() else {
                return;
            };
            let iface_bind_addrs =
                this.interfaces
                    .iter_mut()
                    .filter_map(|entry| match entry.key() {
                        BindAddr::Socket(SocketBindAddr::Iface(bind_addr)) => {
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
                if (iface_ctx.iface.real_addr()).is_ok_and(|read_addr| {
                    !iface_ctx.task.is_finished() && read_addr == RealAddr::Inet(socket_addr)
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
        factory: Arc<dyn ProductQuicInterface>,
    ) -> io::Result<Arc<BorrowedInterface>> {
        match self.interfaces.entry(bind_addr.clone()) {
            dashmap::Entry::Occupied(..) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Interface already exists for {bind_addr}"),
            )),
            dashmap::Entry::Vacant(entry) => {
                let iface_ctx = InterfaceContext::new(bind_addr, factory)?;
                let borrowed_iface = Arc::new(BorrowedInterface::new(
                    iface_ctx.bind_addr.clone(),
                    Arc::downgrade(&iface_ctx.iface),
                    self.clone(),
                ));

                entry.insert((iface_ctx, Arc::downgrade(&borrowed_iface)));
                Ok(borrowed_iface)
            }
        }
    }

    pub fn get(&self, bind_addr: &BindAddr) -> Option<Arc<BorrowedInterface>> {
        self.interfaces
            .get(bind_addr)
            .and_then(|entry| entry.value().1.upgrade())
    }

    pub fn remove(&self, bind_addr: BindAddr) {
        self.interfaces.remove(&bind_addr);
    }
}

pub struct InterfaceContext {
    bind_addr: BindAddr,
    /// factory to rebind the interface
    ///
    /// factory may be changed when manually rebind
    factory: Arc<dyn ProductQuicInterface>,
    /// the actual interface being used
    ///
    /// the actual interface may be changed when rebind
    iface: Arc<RwInterface>,
    /// recv task handle
    task: JoinHandle<()>,
}

impl InterfaceContext {
    pub fn new(bind_addr: BindAddr, factory: Arc<dyn ProductQuicInterface>) -> io::Result<Self> {
        let iface = factory.bind(bind_addr.clone())?;
        let iface = Arc::new(RwInterface::from(iface));

        let task = tokio::spawn(Router::global().deliver_all(Box::pin(
            RwInterface::received_packets_stream(Arc::downgrade(&iface)),
        )));

        Ok(InterfaceContext {
            bind_addr,
            factory,
            iface,
            task,
        })
    }

    pub async fn rebind(&mut self, bind_addr: BindAddr) -> io::Result<()> {
        self.iface.update(self.factory.bind(bind_addr.clone())?);

        // abort the current task
        self.task.abort();
        _ = (&mut self.task).await;
        // then spawn the new one
        self.task = tokio::spawn(Router::global().deliver_all(Box::pin(
            RwInterface::received_packets_stream(Arc::downgrade(&self.iface)),
        )));

        Ok(())
    }
}

impl Drop for InterfaceContext {
    fn drop(&mut self) {
        // When the context is dropped, we abort the task that is managing this interface.
        self.task.abort();
    }
}
