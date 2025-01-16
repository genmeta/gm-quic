use std::sync::{Arc, LazyLock};

pub use client::{QuicClient, QuicClientBuilder};
use qconnection::prelude::QuicProto;
pub use qconnection::{
    builder::{
        ClientParameters, ConsistentConcurrency, ControlConcurrency, DemandConcurrency,
        NoopTokenRegistry, ServerParameters, TokenProvider, TokenSink,
    },
    prelude::{
        Connection, StreamId, StreamReader, StreamWriter, UnreliableReader, UnreliableWriter,
    },
};
pub use server::{QuicServer, QuicServerBuilder, QuicServerSniBuilder};
use tokio::sync::mpsc;

mod client;
mod server;
mod util;

pub mod prelude {
    pub use qconnection::prelude::*;
}

static PROTO: LazyLock<Arc<prelude::QuicProto>> = LazyLock::new(|| {
    let (unrouted_packets_tx, mut unrouted_packets_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some((packet, pathway)) = unrouted_packets_rx.recv().await {
            QuicServer::try_accpet_connection(packet, pathway).await;
        }
    });
    Arc::new(QuicProto::with_listener(Box::new(
        move |_, packet, pathway| {
            _ = unrouted_packets_tx.send((packet, pathway));
        },
    )))
});
