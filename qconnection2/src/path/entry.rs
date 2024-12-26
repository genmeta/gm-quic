use std::{convert::Infallible, sync::Arc};

use futures::{channel::mpsc, FutureExt, StreamExt};
use qbase::packet::{self, Packet};

use crate::{
    builder, event,
    path::Path,
    router,
    space::{data, handshake, initial},
    util::{adapter, subscribe},
};

pub type PacketEntry =
    Box<dyn subscribe::Subscribe<(Packet, Arc<Path>), Error = Infallible> + Send + Sync>;

pub(super) fn generator(
    spaces: builder::Spaces,
    components: builder::Components,
    event_broker: event::EventBroker,
) -> impl Fn() -> PacketEntry {
    use subscribe::Subscribe;
    // A future that yield the packet entry
    let get_entry = initial::PacketEntry::new(spaces.initial, components.clone());
    // pin it to the heap or rustc will complain
    let get_entry = Box::pin(get_entry);
    // make the returned entry cheep to clone(not necessary)
    let get_entry = get_entry.map(|opt| opt.map(Arc::new));
    // adapte the future to a future that can be waited concurrently
    let get_initial_entry = Arc::new(adapter::Concurrent::new(get_entry));

    // same as initial...
    let get_entry = handshake::PacketEntry::new(spaces.handshake, event_broker.clone());
    let get_entry = Box::pin(get_entry);
    let get_entry = get_entry.map(|opt| opt.map(Arc::new));
    let get_handshake_entry = Arc::new(adapter::Concurrent::new(get_entry));

    let get_entry = data::ZeroRttPacketEntry::new(spaces.data.clone(), components.clone());
    let get_entry = Box::pin(get_entry);
    let get_entry = get_entry.map(|opt| opt.map(Arc::new));
    let get_zero_rtt_entry = Arc::new(adapter::Concurrent::new(get_entry));

    let get_entry =
        data::OneRttPacketEntry::new(spaces.data, components.clone(), event_broker.clone());
    let get_entry = Box::pin(get_entry);
    let get_entry = get_entry.map(|opt| opt.map(Arc::new));
    let get_one_rtt_entry = Arc::new(adapter::Concurrent::new(get_entry));

    move || {
        let (initial_entry, mut packets) = mpsc::unbounded::<(_, Arc<Path>)>();
        let initial = {
            let event_broker = event_broker.clone();
            let get_entry = get_initial_entry.clone();
            async move {
                let Some(entry) = get_entry.poll().await.clone() else {
                    return;
                };
                while let Some((pkt, path)) = packets.next().await {
                    if let Err(error) = entry.deliver((pkt, &path)) {
                        _ = event_broker.deliver(event::ConnEvent::TransportError(error));
                    }
                }
            }
        };

        let (handshake_entry, mut packets) = mpsc::unbounded::<(_, Arc<Path>)>();
        let handshake = {
            let event_broker = event_broker.clone();
            let get_entry = get_handshake_entry.clone();
            async move {
                let Some(entry) = get_entry.poll().await.clone() else {
                    return;
                };
                while let Some((pkt, path)) = packets.next().await {
                    if let Err(error) = entry.deliver((pkt, &path)) {
                        _ = event_broker.deliver(event::ConnEvent::TransportError(error));
                    }
                }
            }
        };

        let (zero_rtt_entry, mut packets) = mpsc::unbounded::<(_, Arc<Path>)>();
        let zero_rtt = {
            let event_broker = event_broker.clone();
            let get_entry = get_zero_rtt_entry.clone();
            async move {
                let Some(entry) = get_entry.poll().await.clone() else {
                    return;
                };
                while let Some((pkt, path)) = packets.next().await {
                    if let Err(error) = entry.deliver((pkt, &path)) {
                        _ = event_broker.deliver(event::ConnEvent::TransportError(error));
                    }
                }
            }
        };

        let (one_rtt_entry, mut packets) = mpsc::unbounded::<(_, Arc<Path>)>();
        let one_rtt = {
            let event_broker = event_broker.clone();
            let get_entry = get_one_rtt_entry.clone();
            async move {
                let Some(entry) = get_entry.poll().await.clone() else {
                    return;
                };
                while let Some((pkt, path)) = packets.next().await {
                    if let Err(error) = entry.deliver((pkt, &path)) {
                        _ = event_broker.deliver(event::ConnEvent::TransportError(error));
                    }
                }
            }
        };

        tokio::spawn(async move {
            tokio::join!(initial, handshake, zero_rtt, one_rtt);
        });

        let packet_entry = move |(pkt, path): (Packet, Arc<Path>)| match pkt {
            Packet::VN(_vn) => todo!(),
            Packet::Retry(_retry) => todo!(),
            Packet::Data(data_packet) => match data_packet.header {
                packet::DataHeader::Long(packet::long::DataHeader::Initial(hdr)) => {
                    _ = initial_entry
                        .unbounded_send(((hdr, data_packet.bytes, data_packet.offset), path))
                }
                packet::DataHeader::Long(packet::long::DataHeader::Handshake(hdr)) => {
                    _ = handshake_entry
                        .unbounded_send(((hdr, data_packet.bytes, data_packet.offset), path))
                }
                packet::DataHeader::Long(packet::long::DataHeader::ZeroRtt(hdr)) => {
                    _ = zero_rtt_entry
                        .unbounded_send(((hdr, data_packet.bytes, data_packet.offset), path))
                }
                packet::DataHeader::Short(hdr) => {
                    _ = one_rtt_entry
                        .unbounded_send(((hdr, data_packet.bytes, data_packet.offset), path))
                }
            },
        };
        Box::new(move |arg| {
            packet_entry(arg);
            Ok(())
        }) as _
    }
}

pub struct ReceivingPipeline {
    path: Arc<Path>,
    packets: subscribe::ResourceLease<Arc<router::ConnInterface>, super::Pathway>,
    entry: PacketEntry,
}

impl super::Path {
    pub fn new_receiving_pipeline(self: &Arc<Self>, entry: PacketEntry) -> ReceivingPipeline {
        use subscribe::Publish;
        let packets = self.conn_if.resources_viewer(self.way).into_lease();
        ReceivingPipeline {
            path: self.clone(),
            packets,
            entry,
        }
    }
}

impl ReceivingPipeline {
    pub fn begin_recving<F>(mut self, on_failed: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce() + Send + 'static,
    {
        use futures::StreamExt;
        tokio::spawn(async move {
            while let Some(pkt) = self.packets.next().await {
                _ = self.entry.deliver((pkt, self.path.clone()));
            }
            on_failed();
        })
    }
}
