use std::{
    fmt::{Debug, Display},
    io,
};

use futures::{FutureExt, TryFutureExt, future::BoxFuture, stream::BoxStream};
use qbase::net::{
    Family,
    addr::{EndpointAddr, SocketEndpointAddr},
};

pub type PublishFuture<'a> = BoxFuture<'a, io::Result<()>>;

pub trait Publisher: Display + Debug {
    fn publish<'a>(&self, name: &'a str, endpoints: &'a [EndpointAddr]) -> PublishFuture<'a>;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Source {
    Mdns { nic: String, family: Family },
    Http { server: String },
    System,
    Dht,
}

// gm-quic -> resolve trait
// gmdns -> h3x
//       -> resolve trait

pub type Record = (Source, EndpointAddr);
pub type RecordStream<'a> = BoxStream<'a, Record>;
pub type ResolveResult<'a> = io::Result<RecordStream<'a>>;
pub type ResolveFuture<'a> = BoxFuture<'a, ResolveResult<'a>>;

/// Resolves names into QUIC peer endpoints.
///
/// The result is a stream to allow implementations that yield endpoints over time
/// (e.g. multi-source resolvers, H3x Dns, Mdns).
pub trait Resolve: Send + Sync + Debug {
    fn lookup<'a>(&'a self, name: &'a str) -> ResolveFuture<'a>;
}

use futures::{StreamExt, stream};

/// Default resolver backed by `tokio::net::lookup_host`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Display for SystemResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "System DNS Resolver")
    }
}

impl Resolve for SystemResolver {
    fn lookup<'a>(&'a self, name: &'a str) -> BoxFuture<'a, io::Result<RecordStream<'a>>> {
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
