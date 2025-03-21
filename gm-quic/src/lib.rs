use std::sync::{Arc, LazyLock};

pub use qconnection::{
    builder::{
        ClientParameters, ConnectionId, ConsistentConcurrency, ControlConcurrency,
        DemandConcurrency, NoopTokenRegistry, ServerParameters, TokenProvider, TokenSink,
    },
    prelude::*,
};

pub use crate::{
    cert::{ToCertificate, ToPrivateKey},
    client::{QuicClient, QuicClientBuilder},
    fractor::ProductQuicInterface,
    interfaces::Interfaces,
    server::{QuicServer, QuicServerBuilder, QuicServerSniBuilder},
};

mod cert;
mod client;
mod fractor;
mod interfaces;
mod server;
#[cfg(test)]
mod tests;

pub mod prelude {
    pub use qconnection::prelude::*;
}

static PROTO: LazyLock<Arc<prelude::QuicProto>> = LazyLock::new(|| {
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
