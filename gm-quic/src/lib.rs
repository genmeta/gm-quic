use std::sync::{Arc, LazyLock};

pub use qconnection::{
    builder::{
        ClientParameters, ConnectionId, ConsistentConcurrency, ControlStreamsConcurrency,
        DemandConcurrency, NoopTokenRegistry, ServerParameters, TokenProvider, TokenSink,
    },
    prelude::*,
};
pub use qinterface::factory::ProductQuicInterface;

pub use crate::{
    cert::{ToCertificate, ToPrivateKey},
    client::{QuicClient, QuicClientBuilder},
    interfaces::Interfaces,
    server::{QuicServer, QuicServerBuilder, QuicServerSniBuilder},
};

mod cert;
mod client;
mod interfaces;
mod server;
#[cfg(test)]
mod tests;

static PROTO: LazyLock<Arc<QuicProto>> = LazyLock::new(|| {
    let proto = Arc::new(QuicProto::new());
    tokio::spawn({
        let proto = proto.clone();
        async move {
            while let Some((packet, pathway, socket)) = proto.recv_unrouted_packet().await {
                QuicServer::try_accpet_connection(packet, pathway, socket).await;
            }
        }
    });

    proto
});
