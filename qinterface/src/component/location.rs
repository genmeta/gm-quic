use std::{
    any::{Any, TypeId},
    collections::{HashMap, hash_map},
    fmt::Debug,
    ops::Deref,
    sync::{Arc, LazyLock, Mutex, MutexGuard},
    task::{Context, Poll},
};

use qbase::util::{UniqueId, UniqueIdGenerator};
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    BindUri, Interface, WeakInterface,
    component::Component,
    io::{IO, RefIO},
};

#[derive(Debug)]
pub enum AddressEvent<D: ?Sized = dyn Any + Send + Sync> {
    Upsert(Arc<D>),
    Remove(TypeId),
    Closed,
}

impl<D: ?Sized> Clone for AddressEvent<D> {
    fn clone(&self) -> Self {
        match self {
            Self::Upsert(arg0) => Self::Upsert(arg0.clone()),
            Self::Remove(arg0) => Self::Remove(*arg0),
            Self::Closed => Self::Closed,
        }
    }
}

impl AddressEvent {
    pub fn downcast<D: Any + Send + Sync>(self) -> Result<AddressEvent<D>, Self> {
        match self {
            AddressEvent::Upsert(data) => match data.downcast::<D>() {
                Ok(data) => Ok(AddressEvent::Upsert(data)),
                Err(data) => Err(AddressEvent::Upsert(data)),
            },
            AddressEvent::Remove(type_id) => match TypeId::of::<D>() == type_id {
                true => Ok(AddressEvent::Remove(type_id)),
                false => Err(AddressEvent::Remove(type_id)),
            },
            AddressEvent::Closed => Ok(AddressEvent::Closed),
        }
    }
}

type EventSender = mpsc::UnboundedSender<(BindUri, AddressEvent)>;
type EventReceiver = mpsc::UnboundedReceiver<(BindUri, AddressEvent)>;

struct EventPublisher {
    subscriber_id_generator: UniqueIdGenerator,
    datas: HashMap<BindUri, HashMap<TypeId, Arc<dyn Any + Send + Sync>>>,
    subscribers: HashMap<UniqueId, EventSender>,
}

impl EventPublisher {
    pub fn new() -> Self {
        Self {
            subscriber_id_generator: UniqueIdGenerator::new(),
            datas: HashMap::new(),
            subscribers: HashMap::new(),
        }
    }

    pub fn publish_event(&mut self, bind_uri: BindUri, event: AddressEvent) {
        // 1. update state
        match event.clone() {
            AddressEvent::Upsert(data) => {
                let type_id = data.as_ref().type_id();
                self.datas
                    .entry(bind_uri.clone())
                    .or_default()
                    .insert(type_id, data);
            }
            AddressEvent::Remove(type_id) => {
                let entry = self.datas.entry(bind_uri.clone());
                if let hash_map::Entry::Occupied(mut entry) = entry {
                    entry.get_mut().remove(&type_id);
                    if entry.get().is_empty() {
                        entry.remove_entry();
                    }
                }
            }
            AddressEvent::Closed => _ = self.datas.remove(&bind_uri),
        }
        // 2. forward event to subscribers
        self.subscribers
            .retain(|_, subscriber| subscriber.send((bind_uri.clone(), event.clone())).is_ok());
    }

    pub fn register_subscriber(&mut self, subscriber: EventSender) {
        let subscriber_id = self.subscriber_id_generator.generate();
        for (bind_uri, datas) in &self.datas {
            for (.., data) in datas {
                let event = AddressEvent::Upsert(data.clone());
                if subscriber.send((bind_uri.clone(), event)).is_err() {
                    // EventReceiver disconnected, so we skip registering this subscriber.
                    return;
                }
            }
        }
        self.subscribers.insert(subscriber_id, subscriber);
    }
}

#[derive(Debug)]
pub struct Locations {
    new_event_tx: EventSender,
    new_subscriber_tx: mpsc::UnboundedSender<EventSender>,
    _publisher_task: AbortOnDropHandle<()>,
}

impl Default for Locations {
    fn default() -> Self {
        Self::new()
    }
}

impl Locations {
    pub fn new() -> Self {
        let (new_event_tx, mut new_event_rx) = mpsc::unbounded_channel::<(BindUri, AddressEvent)>();
        let (new_subscriber_tx, mut new_subscriber_rx) = mpsc::unbounded_channel();

        let _publisher_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut publisher = EventPublisher::new();

            loop {
                tokio::select! {
                    Some((bind_uri, event)) = new_event_rx.recv() => {
                        publisher.publish_event(bind_uri, event);
                    }
                    Some(new_subscriber) = new_subscriber_rx.recv() => {
                        publisher.register_subscriber(new_subscriber);
                    }
                    else => break
                }
            }
        }));

        Self {
            new_event_tx,
            new_subscriber_tx,
            _publisher_task,
        }
    }

    pub fn global() -> &'static Arc<Self> {
        static GLOBAL: LazyLock<Arc<Locations>> = LazyLock::new(|| Arc::new(Locations::new()));
        &GLOBAL
    }

    pub fn publish(&self, bind_uri: BindUri, event: AddressEvent) {
        _ = self.new_event_tx.send((bind_uri, event));
    }

    pub fn upsert<D: Any + Send + Sync + Debug>(&self, bind_uri: BindUri, data: Arc<D>) {
        tracing::debug!(%bind_uri, ?data, "Upsert location data");
        self.publish(bind_uri, AddressEvent::Upsert(data));
    }

    pub fn remove<D: Any + Send + Sync>(&self, bind_uri: BindUri) {
        self.publish(bind_uri, AddressEvent::Remove(TypeId::of::<D>()));
    }

    pub fn close(&self, bind_uri: BindUri) {
        self.publish(bind_uri, AddressEvent::Closed);
    }

    pub fn subscribe(&self) -> Observer {
        let (tx, rx) = mpsc::unbounded_channel();
        // Register the new subscriber.
        _ = self.new_subscriber_tx.send(tx);
        Observer { receiver: rx }
    }
}

pub struct Observer {
    receiver: EventReceiver,
}

impl Observer {
    pub async fn recv(&mut self) -> Option<(BindUri, AddressEvent)> {
        self.receiver.recv().await
    }

    pub fn try_recv(&mut self) -> Result<(BindUri, AddressEvent), mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }
}

#[derive(Debug, Clone)]
pub struct IfaceLocations<I> {
    locations: Arc<Locations>,
    ref_iface: Arc<Mutex<I>>,
}

impl<I: RefIO + 'static> IfaceLocations<I> {
    pub fn new(ref_iface: I, locations: Arc<Locations>) -> Self {
        locations.upsert(
            ref_iface.iface().bind_uri(),
            Arc::new(ref_iface.iface().real_addr()),
        );

        Self {
            locations,
            ref_iface: Arc::new(Mutex::new(ref_iface)),
        }
    }

    fn lock_ref_iface(&self) -> MutexGuard<'_, I> {
        self.ref_iface.lock().expect("Mutex poisoned")
    }

    /// Scope operation to the newest interface.
    pub fn r#for<R>(&self, ref_iface: &R, f: impl FnOnce(&Locations, BindUri))
    where
        R: RefIO + 'static,
    {
        let current_iface = self.lock_ref_iface();
        let current_iface = current_iface.deref();
        if !(ref_iface as &dyn Any)
            .downcast_ref::<I>()
            .is_some_and(|ref_iface| ref_iface.same_io(current_iface))
        {
            return;
        }
        f(&self.locations, current_iface.iface().bind_uri());
    }
}

pub type LocationsComponent = IfaceLocations<WeakInterface>;

impl Component for LocationsComponent {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
        _ = cx;
        Poll::Ready(())
    }

    fn reinit(&self, iface: &Interface) {
        let mut ref_iface = self.lock_ref_iface();
        if iface.downgrade().same_io(ref_iface.deref()) {
            return;
        }
        *ref_iface = iface.downgrade();
        let bind_uri = iface.bind_uri();

        self.locations.close(bind_uri.clone());
        self.locations
            .upsert(bind_uri.clone(), Arc::new(iface.real_addr()));
    }
}
