use std::sync::OnceLock;

pub use qconnection::{
    builder::{
        ClientParameters, ControlStreamsConcurrency, ServerParameters, TokenProvider, TokenSink,
    },
    prelude::*,
};
pub use qinterface::factory::ProductQuicIO;

pub use crate::{
    cert::{ToCertificate, ToPrivateKey},
    client::{ConnectEndpointError, ConnectServerError, QuicClient, QuicClientBuilder},
    server::{BuildServerError, QuicListeners, QuicListenersBuilder, ServerError},
};

mod cert;
mod client;
mod server;
#[cfg(test)]
mod tests;
