use std::{
    fmt::{Debug, Display},
    io,
    sync::Arc,
};

use futures::{FutureExt, TryFutureExt, future::BoxFuture, stream::BoxStream};
pub use qbase::net::{
    Family,
    addr::{BleEndpontAddr, EndpointAddr, SocketEndpointAddr},
};

pub type PublishFuture<'a> = BoxFuture<'a, io::Result<()>>;

pub trait Publish: Display + Debug {
    fn publish<'a>(&'a self, name: &'a str, endpoints: &'a [EndpointAddr]) -> PublishFuture<'a>;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Source {
    Mdns { nic: Arc<str>, family: Family },
    Http { server: Arc<str> },
    System,
    Dht,
}

impl Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Mdns { nic, family } => write!(f, "mDNS Resolver({nic} {family})"),
            Source::Http { server } => write!(f, "HTTP DNS Resolver({server})"),
            Source::System => write!(f, "System DNS Resolver"),
            Source::Dht => write!(f, "DHT"),
        }
    }
}

pub type Record = (Source, EndpointAddr);
pub type RecordStream<'n> = BoxStream<'n, Record>;
pub type ResolveResult<'n> = io::Result<RecordStream<'n>>;
pub type ResolveFuture<'r, 'n> = BoxFuture<'r, ResolveResult<'n>>;

/// Resolves names into QUIC peer endpoints.
///
/// The result is a stream to allow implementations that yield endpoints over time
/// (e.g. multi-source resolvers, H3x Dns, Mdns).
pub trait Resolve: Send + Sync + Display + Debug {
    fn lookup<'r, 'n: 'r>(&'r self, name: &'n str) -> ResolveFuture<'r, 'n>;
}

use futures::{StreamExt, stream};

/// Default resolver backed by `tokio::net::lookup_host`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Display for SystemResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&Source::System, f)
    }
}

impl Resolve for SystemResolver {
    fn lookup<'r, 'n: 'r>(&'r self, name: &'n str) -> ResolveFuture<'r, 'n> {
        let source = Source::System;
        tokio::net::lookup_host(name)
            .map_ok(move |addrs| {
                stream::iter(addrs.map(move |addr| {
                    let ep = EndpointAddr::Socket(SocketEndpointAddr::direct(addr));
                    (source.clone(), ep)
                }))
                .boxed()
            })
            .boxed()
    }
}
