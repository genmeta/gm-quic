use std::sync::{Arc, LazyLock};

use qconnection::prelude::QuicProto;
pub use qconnection::{
    builder::{
        ClientParameters, ConnectionId, ConsistentConcurrency, ControlConcurrency,
        DemandConcurrency, NoopTokenRegistry, ServerParameters, TokenProvider, TokenSink,
    },
    prelude::{
        Connection, Pathway, QuicInterface, Socket, StreamId, StreamReader, StreamWriter,
        UnreliableReader, UnreliableWriter,
    },
};

pub use crate::{
    client::{QuicClient, QuicClientBuilder},
    interfaces::Interfaces,
    server::{QuicServer, QuicServerBuilder, QuicServerSniBuilder},
};

mod client;
mod interfaces;
mod server;
mod util;

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
