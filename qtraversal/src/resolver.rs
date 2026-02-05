use std::{fmt::Debug, io};

use futures::{FutureExt, TryFutureExt, future::BoxFuture, stream::BoxStream};
use qbase::net::addr::SocketEndpointAddr;
use qinterface::bind_uri::BindUri;

pub type ResolveItem = (Option<BindUri>, SocketEndpointAddr);
pub type ResolveStream<'a> = BoxStream<'a, ResolveItem>;

/// Resolves names into QUIC peer endpoints.
///
/// The result is a stream to allow implementations that yield endpoints over time
/// (e.g. multi-source resolvers, H3x Dns, Mdns).
pub trait Resolve: Send + Sync + Debug {
    fn lookup<'a>(&'a self, name: &'a str) -> BoxFuture<'a, io::Result<ResolveStream<'a>>>;
}

use futures::{StreamExt, stream};

/// Default resolver backed by `tokio::net::lookup_host`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StandResolver;

impl Resolve for StandResolver {
    fn lookup<'a>(&'a self, name: &'a str) -> BoxFuture<'a, io::Result<ResolveStream<'a>>> {
        tokio::net::lookup_host(name)
            .map_ok(|addrs| {
                stream::iter(addrs.map(|addr| (None, SocketEndpointAddr::direct(addr)))).boxed()
            })
            .boxed()
    }
}
