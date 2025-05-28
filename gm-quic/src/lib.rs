use std::sync::{Arc, OnceLock};

pub use qconnection::{
    builder::{
        ClientParameters, ConnectionId, ConsistentConcurrency, ControlStreamsConcurrency,
        ServerParameters, TokenProvider, TokenSink,
    },
    prelude::*,
};
pub use qinterface::factory::ProductQuicInterface;

pub use crate::{
    cert::{ToCertificate, ToPrivateKey},
    client::{QuicClient, QuicClientBuilder},
    server::{Host, HostBuilder, QuicListeners, QuicListenersBuilder},
};

mod cert;
mod client;
mod server;
#[cfg(test)]
mod tests;

pub fn proto() -> &'static Arc<QuicProto> {
    static PROTO: OnceLock<Arc<QuicProto>> = OnceLock::new();
    PROTO.get_or_init(|| {
        let proto = Arc::new(QuicProto::new());
        let handle_unrouted_packets = {
            let proto = proto.clone();
            async move {
                while let Some((iface_addr, packet, pathway, ink)) =
                    proto.recv_unrouted_packet().await
                {
                    QuicListeners::try_accept_connection(iface_addr, packet, pathway, ink).await;
                }
            }
        };
        let handle_broken_interfaces = {
            let proto = proto.clone();
            async move {
                while let Some((local_addr, iface, error)) = proto.get_broken_interface().await {
                    QuicListeners::on_interface_broken(local_addr, iface, error);
                }
            }
        };
        tokio::spawn(async move {
            tokio::join!(handle_unrouted_packets, handle_broken_interfaces);
        });
        proto
    })
}
