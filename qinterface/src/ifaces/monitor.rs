use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, OnceLock, RwLock, RwLockReadGuard},
    time::Duration,
};

use netdev::Interface;
use qbase::net::address::{IfaceBindAddr, IpFamily};
use tokio::sync::watch;

struct Devices(RwLock<HashMap<String, Interface>>);

impl Default for Devices {
    fn default() -> Self {
        Self(RwLock::new(HashMap::new()))
    }
}

impl Devices {
    fn get(&self) -> RwLockReadGuard<'_, HashMap<String, Interface>> {
        self.0.read().unwrap()
    }

    fn update(&self) {
        *self.0.write().unwrap() = netdev::get_interfaces()
            .into_iter()
            .map(|iface| (iface.name.clone(), iface))
            .collect();
    }
}

pub struct InterfacesMonitor {
    devices: Arc<Devices>,
    updated_tx: watch::Sender<()>,
    updated_rx: watch::Receiver<()>,
    task: tokio::task::JoinHandle<()>,
}

impl InterfacesMonitor {
    pub fn global() -> &'static InterfacesMonitor {
        static MONITOR: OnceLock<InterfacesMonitor> = OnceLock::new();
        MONITOR.get_or_init(Self::new)
    }

    pub fn new() -> Self {
        let devices = Arc::new(Devices::default());

        let (updated_tx, updated_rx) = watch::channel(());

        let task = tokio::spawn({
            let devices = devices.clone();
            let timer_tx = updated_tx.clone();
            // let event_tx = updated_tx.clone();
            async move {
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(5));
                    loop {
                        interval.tick().await;
                        devices.update();
                        if timer_tx.send(()).is_err() {
                            break;
                        }
                    }
                });

                // tokio::spawn(async move {
                //     if let Ok(monitor) = netwatch::netmon::Monitor::new().await {
                //         let cb = move |is_major| {
                //             if is_major {
                //                 _ = event_tx.send(());
                //             }
                //             Box::pin(async move {}) as futures::future::BoxFuture<'static, ()>
                //         };
                //         _ = monitor.subscribe(cb).await;
                //     }
                // });
            }
        });

        Self {
            devices,
            updated_tx,
            updated_rx,
            task,
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.updated_rx.clone()
    }

    pub fn on_interface_changed(&self) {
        self.devices.update();
        self.updated_tx.send(()).unwrap();
    }

    pub fn devices(&self) -> RwLockReadGuard<'_, HashMap<String, Interface>> {
        self.devices.get()
    }

    pub fn get(&self, bind_addr: &IfaceBindAddr) -> Option<SocketAddr> {
        self.devices()
            .get(bind_addr.device_name())
            .and_then(|interface| match bind_addr.ip_family() {
                IpFamily::V4 => interface
                    .ipv4
                    .first()
                    .map(|ipnet| SocketAddr::new(ipnet.addr().into(), bind_addr.port().into())),
                IpFamily::V6 => interface
                    .ipv6
                    .iter()
                    .map(|ipnet| ipnet.addr())
                    .find(|ip| !matches!(ip.octets(), [0xfe, 0x80, ..]))
                    .map(|ip| SocketAddr::new(ip.into(), bind_addr.port().into())),
            })
    }
}

impl Default for InterfacesMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for InterfacesMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}
