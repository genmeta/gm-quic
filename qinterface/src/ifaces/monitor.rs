use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use dashmap::DashMap;
use netdev::Interface;
use netwatch::netmon::Monitor;
use tokio::sync::{mpsc, watch};

pub struct InterfacesMonitor {
    devices: Arc<DashMap<String, Interface>>,
    update_tx: mpsc::Sender<()>,
    updated_rx: watch::Receiver<()>,
    task: tokio::task::JoinHandle<()>,
}

impl InterfacesMonitor {
    pub fn global() -> &'static InterfacesMonitor {
        static MONITOR: OnceLock<InterfacesMonitor> = OnceLock::new();
        MONITOR.get_or_init(Self::new)
    }

    pub fn new() -> Self {
        let devices: Arc<DashMap<String, Interface>> = Arc::default();

        for interface in netdev::get_interfaces() {
            devices.insert(interface.name.clone(), interface);
        }

        let (update_tx, mut updata_rx) = mpsc::channel(2);
        let (updated_tx, updated_rx) = watch::channel(());

        let task = tokio::spawn({
            let devices = devices.clone();
            let update_tx = update_tx.clone();
            async move {
                tokio::spawn({
                    let update_tx = update_tx.clone();
                    async move {
                        let mut interval = tokio::time::interval(Duration::from_secs(5));
                        loop {
                            interval.tick().await;
                            if update_tx.send(()).await.is_err() {
                                break;
                            };
                        }
                    }
                });

                tokio::spawn(async move {
                    if let Ok(monitor) = Monitor::new().await {
                        let cb = move |is_major| {
                            let update_tx = update_tx.clone();
                            Box::pin(async move {
                                if is_major {
                                    _ = update_tx.send(()).await;
                                }
                            })
                                as futures::future::BoxFuture<'static, ()>
                        };
                        _ = monitor.subscribe(cb).await;
                    }
                });

                while updata_rx.recv().await.is_some() {
                    for interface in netdev::get_interfaces() {
                        devices.insert(interface.name.clone(), interface);
                    }
                    _ = updated_tx.send(());
                }
            }
        });

        Self {
            devices,
            update_tx,
            updated_rx,
            task,
        }
    }

    pub fn watcher(&self) -> watch::Receiver<()> {
        self.updated_rx.clone()
    }

    pub fn on_interface_changed(&self) {
        _ = self.update_tx.try_send(());
    }

    pub fn devices(&self) -> &DashMap<String, Interface> {
        &self.devices
    }
}

impl Drop for InterfacesMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn feature() {
    let mut watcher = InterfacesMonitor::global().watcher();

    if watcher.changed().await.is_ok() {
        dbg!(InterfacesMonitor::global().devices());
    }
}
