use std::sync::{Mutex, MutexGuard};

use qbase::packet::Packet;

use super::Way;

pub type PacketSink<P = Packet> = Box<dyn Fn(P, Way) + Send>;

pub struct PacketHandler<P = Packet>(Mutex<Option<PacketSink<P>>>);

impl<P> std::fmt::Debug for PacketHandler<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketHandler").finish()
    }
}

impl<P> Default for PacketHandler<P> {
    fn default() -> Self {
        Self::drain()
    }
}

impl<P> PacketHandler<P> {
    pub fn new<S>(sink: PacketSink<P>) -> Self {
        Self(Mutex::new(Some(sink)))
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Option<PacketSink<P>>> {
        self.0.lock().expect("PacketHandler mutex poisoned")
    }

    pub fn drain() -> PacketHandler<P> {
        PacketHandler(Mutex::new(None))
    }

    pub fn update(&self, handler: PacketSink<P>) {
        *self.lock() = Some(handler);
    }

    pub fn is_drain(&self) -> bool {
        self.lock().is_none()
    }

    pub fn take(&self) -> Option<PacketSink<P>> {
        self.lock().take()
    }

    pub fn deliver(&self, packet: P, way: Way) {
        if let Some(sink) = self.lock().as_mut() {
            sink(packet, way);
        }
    }

    pub fn deliver_packets(&self, packets: impl IntoIterator<Item = (P, Way)>) {
        if let Some(sink) = self.lock().as_mut() {
            for (packet, way) in packets {
                sink(packet, way);
            }
        }
    }
}
