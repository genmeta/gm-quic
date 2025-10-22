use std::{
    collections::HashMap,
    sync::{Arc, OnceLock, RwLock, RwLockReadGuard},
    time::Duration,
};

pub use netdev::Interface;
use tokio::{sync::watch, time::MissedTickBehavior};
use tokio_util::task::AbortOnDropHandle;

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
            .map(|mut iface| {
                // compatibility with windows interface names
                iface.name = iface
                    .name
                    .trim_start_matches('{')
                    .trim_end_matches('}')
                    .to_string();
                iface
            })
            .map(|iface| (iface.name.clone(), iface))
            .collect();
    }
}

pub struct InterfacesMonitor {
    devices: Arc<Devices>,
    updated_tx: watch::Sender<()>,
    updated_rx: watch::Receiver<()>,
    _task: AbortOnDropHandle<()>,
}

impl InterfacesMonitor {
    pub fn global() -> &'static InterfacesMonitor {
        static MONITOR: OnceLock<InterfacesMonitor> = OnceLock::new();
        MONITOR.get_or_init(Self::new)
    }

    pub fn new() -> Self {
        let devices = Arc::new(Devices::default());

        let (updated_tx, updated_rx) = watch::channel(());

        let task = AbortOnDropHandle::new(tokio::spawn({
            let devices = devices.clone();
            let timer_tx = updated_tx.clone();
            // let event_tx = updated_tx.clone();
            async move {
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(5));
                    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
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
        }));

        Self {
            devices,
            updated_tx,
            updated_rx,
            _task: task,
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
}

impl Default for InterfacesMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_name() {
        let global = InterfacesMonitor::global();
        tokio::time::sleep(Duration::from_secs(1)).await;

        for (name, iface) in global.devices().iter() {
            eprintln!("{}: {:?}", name, iface.gateway.as_ref().map(|g| g.mac_addr));
        }

        panic!()
    }
}
