use std::{convert::Infallible, pin::Pin};

use futures::{Sink, SinkExt, StreamExt};
use qbase::packet::Packet;
use tokio::sync::{Mutex, MutexGuard};

use super::Way;

pub type PacketSink<P = Packet> = Pin<Box<dyn Sink<(P, Way), Error = Infallible> + Send>>;

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

    pub(crate) async fn lock(&self) -> MutexGuard<'_, Option<PacketSink<P>>> {
        self.0.lock().await
    }

    pub fn drain() -> PacketHandler<P> {
        PacketHandler(Mutex::new(None))
    }

    pub async fn update(&self, handler: PacketSink<P>) {
        *self.lock().await = Some(handler);
    }

    pub async fn is_drain(&self) -> bool {
        self.lock().await.is_none()
    }

    pub async fn take(&self) -> Option<PacketSink<P>> {
        self.lock().await.take()
    }

    pub async fn deliver(&self, packet: P, way: Way) {
        if let Some(sink) = self.lock().await.as_mut() {
            sink.send((packet, way)).await.ok();
        }
    }

    pub async fn deliver_packets(&self, packets: impl IntoIterator<Item = (P, Way)>) {
        if let Some(sink) = self.lock().await.as_mut() {
            let mut stream = futures::stream::iter(packets).map(Ok);
            sink.send_all(&mut stream).await.ok();
        }
    }
}
