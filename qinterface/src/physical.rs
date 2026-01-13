use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::Duration,
};

use derive_more::{Deref, DerefMut};
pub use netdev::Interface;
pub use netwatcher::Error as WatcherError;
use netwatcher::WatchHandle;
use qbase::util::{UniqueId, UniqueIdGenerator};
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    time::MissedTickBehavior,
};
use tokio_util::task::AbortOnDropHandle;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceEvent {
    Added {
        device: String,
        new_interface: Interface,
    },
    Removed {
        device: String,
        old_interface: Interface,
    },
    Changed {
        device: String,
        old_interface: Interface,
        new_interface: Interface,
    },
}

impl InterfaceEvent {
    pub fn device(&self) -> &str {
        match self {
            InterfaceEvent::Added { device, .. } => device,
            InterfaceEvent::Removed { device, .. } => device,
            InterfaceEvent::Changed { device, .. } => device,
        }
    }

    pub fn old_interface(&self) -> Option<&Interface> {
        match self {
            InterfaceEvent::Removed { old_interface, .. }
            | InterfaceEvent::Changed { old_interface, .. } => Some(old_interface),
            _ => None,
        }
    }

    pub fn new_interface(&self) -> Option<&Interface> {
        match self {
            InterfaceEvent::Added { new_interface, .. }
            | InterfaceEvent::Changed { new_interface, .. } => Some(new_interface),
            _ => None,
        }
    }
}

impl InterfaceEvent {
    pub fn from_update<'i>(
        old_interfaces: &'i HashMap<String, Interface>,
        new_interfaces: &'i HashMap<String, Interface>,
    ) -> impl Iterator<Item = Self> + 'i {
        new_interfaces
            .iter()
            .filter_map(|(name, new_interface)| match old_interfaces.get(name) {
                Some(old_interface) if new_interface != old_interface => {
                    Some(InterfaceEvent::Changed {
                        device: name.to_owned(),
                        old_interface: old_interface.clone(),
                        new_interface: new_interface.clone(),
                    })
                }
                None => Some(InterfaceEvent::Added {
                    device: name.to_owned(),
                    new_interface: new_interface.clone(),
                }),
                _ => None,
            })
            .chain(
                old_interfaces
                    .iter()
                    .filter(|(name, ..)| !new_interfaces.contains_key(*name))
                    .map(|(name, old_interface)| InterfaceEvent::Removed {
                        device: name.to_owned(),
                        old_interface: old_interface.clone(),
                    }),
            )
    }
}

fn scan_interfaces() -> HashMap<String, Interface> {
    netdev::get_interfaces()
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
        .collect()
}

type SubscribersMap = RwLock<HashMap<UniqueId, UnboundedSender<Arc<InterfaceEvent>>>>;
type InterfacesMap = RwLock<HashMap<String, Interface>>;

#[derive(Debug, Deref, DerefMut)]
pub struct InterfaceEventReceiver {
    id: UniqueId,
    #[deref]
    #[deref_mut]
    receiver: UnboundedReceiver<Arc<InterfaceEvent>>,
    subscribers: Arc<SubscribersMap>,
}

impl Drop for InterfaceEventReceiver {
    fn drop(&mut self) {
        self.subscribers.write().unwrap().remove(&self.id);
    }
}

pub struct InterfacesMonitor {
    interfaces: HashMap<String, Interface>,
    receiver: InterfaceEventReceiver,
}

impl InterfacesMonitor {
    #[inline]
    pub async fn update(&mut self) -> Option<(&HashMap<String, Interface>, Arc<InterfaceEvent>)> {
        self.receiver.recv().await.map(|event| {
            match event.as_ref() {
                InterfaceEvent::Added {
                    device,
                    new_interface,
                } => {
                    self.interfaces
                        .insert(device.clone(), new_interface.clone());
                }
                InterfaceEvent::Removed { device, .. } => {
                    self.interfaces.remove(device);
                }
                InterfaceEvent::Changed {
                    device,
                    new_interface,
                    ..
                } => {
                    self.interfaces
                        .insert(device.clone(), new_interface.clone());
                }
            }
            (self.interfaces(), event)
        })
    }

    #[inline]
    pub fn try_update(&mut self) -> Option<(&HashMap<String, Interface>, Arc<InterfaceEvent>)> {
        self.receiver.try_recv().ok().map(|event| {
            match event.as_ref() {
                InterfaceEvent::Added {
                    device,
                    new_interface,
                } => {
                    self.interfaces
                        .insert(device.clone(), new_interface.clone());
                }
                InterfaceEvent::Removed { device, .. } => {
                    self.interfaces.remove(device);
                }
                InterfaceEvent::Changed {
                    device,
                    new_interface,
                    ..
                } => {
                    self.interfaces
                        .insert(device.clone(), new_interface.clone());
                }
            }
            (self.interfaces(), event)
        })
    }

    #[inline]
    pub fn interfaces(&self) -> &HashMap<String, Interface> {
        &self.interfaces
    }

    pub fn into_inner(self) -> (HashMap<String, Interface>, InterfaceEventReceiver) {
        (self.interfaces, self.receiver)
    }
}

#[derive(Debug)]
struct State {
    interfaces: InterfacesMap,
    subscrib_id_generator: UniqueIdGenerator,
    subscribers: Arc<SubscribersMap>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            interfaces: RwLock::new(scan_interfaces()),
            subscrib_id_generator: UniqueIdGenerator::new(),
            subscribers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl State {
    fn check_network_changes(&self) {
        let mut interfaces = self.interfaces.write().unwrap();
        let subscribers = self.subscribers.read().unwrap();
        let old_interfaces = interfaces.clone();
        let new_interfaces = scan_interfaces();
        for event in InterfaceEvent::from_update(&old_interfaces, &new_interfaces) {
            let arc_event = Arc::new(event);
            for sender in subscribers.values() {
                let _ = sender.send(arc_event.clone());
            }
        }
        *interfaces = new_interfaces.clone();
    }

    fn monitor(&self) -> (HashMap<String, Interface>, InterfaceEventReceiver) {
        let mut subscribers = self.subscribers.write().unwrap();
        let interfaces = self.interfaces.read().unwrap().clone();

        let current_interfaces = interfaces;

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let id = self.subscrib_id_generator.generate();
        subscribers.insert(id, tx);
        let observer = InterfaceEventReceiver {
            id,
            receiver: rx,
            subscribers: Arc::clone(&self.subscribers),
        };

        (current_interfaces, observer)
    }

    fn event_receiver(&self) -> InterfaceEventReceiver {
        let mut subscribers = self.subscribers.write().unwrap();

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let id = self.subscrib_id_generator.generate();
        subscribers.insert(id, tx);
        InterfaceEventReceiver {
            id,
            receiver: rx,
            subscribers: Arc::clone(&self.subscribers),
        }
    }

    fn interfaces(&self) -> HashMap<String, Interface> {
        self.interfaces.read().unwrap().clone()
    }

    fn get(&self, name: &str) -> Option<Interface> {
        self.interfaces.read().unwrap().get(name).cloned()
    }
}

pub struct PhysicalInterfaces {
    state: Arc<State>,
    watcher: Mutex<Result<WatchHandle, WatcherError>>,
    _timer: AbortOnDropHandle<()>,
}

impl PhysicalInterfaces {
    pub fn global() -> &'static PhysicalInterfaces {
        static MONITOR: OnceLock<PhysicalInterfaces> = OnceLock::new();
        MONITOR.get_or_init(Self::new)
    }

    pub fn new() -> Self {
        let state = Arc::new(State::default());

        let timer = AbortOnDropHandle::new(tokio::spawn({
            let state = state.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(5));
                interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    state.check_network_changes();
                }
            }
        }));

        let watcher = netwatcher::watch_interfaces({
            let state = state.clone();
            move |_update| {
                // TODO: use the update info to avoid full scan
                state.check_network_changes();
            }
        });

        if let Err(initial_watcher_error) = &watcher {
            tracing::warn!(target: "interface", "Failed to start interfaces watcher: {initial_watcher_error}");
        }

        Self {
            state,
            _timer: timer,
            watcher: watcher.into(),
        }
    }

    #[inline]
    pub fn restart_watcher(&mut self) -> Result<(), WatcherError> {
        let new_watcher = netwatcher::watch_interfaces({
            let state = self.state.clone();
            move |_update| {
                // TODO: use the update info to avoid full scan
                state.check_network_changes();
            }
        })?;
        *self.watcher.lock().unwrap() = Ok(new_watcher);
        Ok(())
    }

    #[inline]
    pub fn on_interface_changed(&self) {
        self.state.check_network_changes();
    }

    #[inline]
    pub fn monitor(&self) -> InterfacesMonitor {
        let (interfaces, receiver) = self.state.monitor();
        InterfacesMonitor {
            interfaces,
            receiver,
        }
    }

    #[inline]
    pub fn event_receiver(&self) -> InterfaceEventReceiver {
        self.state.event_receiver()
    }

    #[inline]
    pub fn interfaces(&self) -> HashMap<String, Interface> {
        self.state.interfaces()
    }

    pub fn get(&self, name: &str) -> Option<Interface> {
        self.state.get(name)
    }
}

impl Default for PhysicalInterfaces {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scan() {
        let global = PhysicalInterfaces::global();
        for interface in global.interfaces().values() {
            eprintln!("{:?}", interface);
        }
    }
}
