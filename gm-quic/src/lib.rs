use std::sync::OnceLock;

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
    server::{QuicListeners, QuicListenersBuilder},
};

mod cert;
mod client;
mod server;
#[cfg(test)]
mod tests;
