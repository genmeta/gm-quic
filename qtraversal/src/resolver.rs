use std::{fmt::Debug, io};

use futures::stream::BoxStream;
use qbase::net::route::SocketEndpointAddr;
use qinterface::bind_uri::BindUri;

pub type ResolveItem = (Option<BindUri>, SocketEndpointAddr);
pub type ResolveStream<'a> = BoxStream<'a, io::Result<ResolveItem>>;

/// Resolves names into QUIC peer endpoints.
///
/// The result is a stream to allow implementations that yield endpoints over time
/// (e.g. multi-source resolvers, H3x Dns, Mdns).
pub trait Resolve: Send + Sync + Debug {
    fn lookup<'a>(&'a self, name: &'a str) -> ResolveStream<'a>;
}

use futures::{StreamExt, stream};

/// Default resolver backed by `tokio::net::lookup_host`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StandResolver;

impl Resolve for StandResolver {
    fn lookup<'a>(&'a self, name: &'a str) -> ResolveStream<'a> {
        let fut = async move {
            match tokio::net::lookup_host(name).await {
                Ok(addrs) => {
                    stream::iter(addrs.map(|addr| Ok((None, SocketEndpointAddr::direct(addr)))))
                        .boxed()
                }
                Err(e) => stream::once(async { Err(e) }).boxed(),
            }
        };

        stream::once(fut).flatten().boxed()
    }
}
