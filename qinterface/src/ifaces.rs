pub mod monitor;
// handy（qudp）是可选的
pub mod handy;

use std::{
    collections::VecDeque,
    io,
    sync::{Arc, OnceLock, Weak},
};

use dashmap::DashMap;
use futures::Stream;
use qbase::net::address::{BindAddr, RealAddr, SocketBindAddr};
use tokio::{
    sync::{OwnedRwLockReadGuard, RwLock},
    task::JoinHandle,
};

use crate::{
    QuicInterface,
    factory::ProductQuicInterface,
    route::{Received, Router},
};

pub struct QuicInterfaces {
    interfaces: DashMap<BindAddr, (InterfaceContext, Weak<Interface>)>,
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
                if (iface_ctx.iface.read().await.real_addr()).is_ok_and(|read_addr| {
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
    ) -> io::Result<Arc<Interface>> {
        match self.interfaces.entry(bind_addr.clone()) {
            dashmap::Entry::Occupied(..) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Interface already exists for {bind_addr}"),
            )),
            dashmap::Entry::Vacant(entry) => {
                let iface_ctx = InterfaceContext::new(bind_addr, factory)?;
                let borrowed_iface = Arc::new(Interface {
                    bind_addr: iface_ctx.bind_addr.clone(),
                    iface: Arc::downgrade(&iface_ctx.iface),
                    ifaces: self.clone(),
                });

                entry.insert((iface_ctx, Arc::downgrade(&borrowed_iface)));
                Ok(borrowed_iface)
            }
        }
    }

    pub fn get(&self, bind_addr: &BindAddr) -> Option<Arc<Interface>> {
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
    iface: Arc<RwLock<Box<dyn QuicInterface>>>,
    /// recv task handle
    task: JoinHandle<()>,
}

impl InterfaceContext {
    pub fn new(bind_addr: BindAddr, factory: Arc<dyn ProductQuicInterface>) -> io::Result<Self> {
        let iface = factory.bind(bind_addr.clone())?;
        let iface = Arc::new(RwLock::new(iface));

        let task = tokio::spawn(Router::global().deliver_all(Box::pin(
            Self::received_packets_stream(Arc::downgrade(&iface)),
        )));

        Ok(InterfaceContext {
            bind_addr,
            factory,
            iface,
            task,
        })
    }

    pub fn from_exist(
        iface: Box<dyn QuicInterface>,
        factory: Arc<dyn ProductQuicInterface>,
    ) -> Self {
        let bind_addr = iface.bind_addr();
        let iface = Arc::new(RwLock::new(iface));

        let task = tokio::spawn(Router::global().deliver_all(Box::pin(
            Self::received_packets_stream(Arc::downgrade(&iface)),
        )));

        InterfaceContext {
            bind_addr,
            factory,
            iface,
            task,
        }
    }

    pub async fn rebind(&mut self, bind_addr: BindAddr) -> io::Result<()> {
        *self.iface.write().await = self.factory.bind(bind_addr.clone())?;

        // abort the current task
        self.task.abort();
        _ = (&mut self.task).await;
        // then spawn the new one
        self.task = tokio::spawn(Router::global().deliver_all(Box::pin(
            Self::received_packets_stream(Arc::downgrade(&self.iface)),
        )));

        Ok(())
    }

    fn received_packets_stream(
        iface: Weak<RwLock<Box<dyn QuicInterface>>>,
    ) -> impl Stream<Item = Received> + Send {
        futures::stream::unfold(
            (iface, vec![], vec![], VecDeque::new()),
            |(iface, mut bufs, mut hdrs, mut pkts)| async move {
                loop {
                    if let Some(rcvd) = pkts.pop_front() {
                        return Some((rcvd, (iface, bufs, hdrs, pkts)));
                    }
                    let iface = iface.upgrade()?.read_owned().await;
                    pkts.extend(iface.recvpkts(&mut bufs, &mut hdrs).await.ok()?);
                }
            },
        )
    }

    pub fn bind_addr(&self) -> BindAddr {
        self.bind_addr.clone()
    }

    pub async fn get(&self) -> BorrowedInterface {
        OwnedRwLockReadGuard::map(self.iface.clone().read_owned().await, |iface| {
            iface.as_ref()
        })
    }
}

impl Drop for InterfaceContext {
    fn drop(&mut self) {
        // When the context is dropped, we abort the task that is managing this interface.
        self.task.abort();
    }
}

/// Return from [`QuicInterfaces::insert`], automatically remove the inserted interface when dropped.
pub struct Interface {
    bind_addr: BindAddr,
    iface: Weak<RwLock<Box<dyn QuicInterface>>>,
    ifaces: Arc<QuicInterfaces>,
}

pub type BorrowedInterface = OwnedRwLockReadGuard<Box<dyn QuicInterface>, dyn QuicInterface>;

impl Interface {
    pub fn bind_addr(&self) -> BindAddr {
        self.bind_addr.clone()
    }

    pub async fn borrow(self: &Arc<Self>) -> io::Result<BorrowedInterface> {
        let unavailable = || {
            io::Error::new(
                io::ErrorKind::NotConnected,
                format!("Interface {} is not available", self.bind_addr),
            )
        };
        let iface_lock = self.iface.upgrade().ok_or_else(unavailable)?;
        Ok(OwnedRwLockReadGuard::map(
            iface_lock.read_owned().await,
            |iface| iface.as_ref(),
        ))
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.ifaces
            .interfaces
            .remove_if(&self.bind_addr, |_, (iface_ctx, _)| {
                Weak::ptr_eq(&Arc::downgrade(&iface_ctx.iface), &self.iface)
            });
    }
}
