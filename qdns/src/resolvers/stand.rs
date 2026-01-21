use std::fmt;

use qbase::net::route::SocketEndpointAddr;
use rustls::{SignatureScheme, sign::SigningKey};
use tokio::{io, net};

use crate::Resolve;

#[derive(Debug, Default, Clone, Copy)]
pub struct StandResolver;

impl StandResolver {
    pub const fn new() -> Self {
        Self
    }
}

impl fmt::Display for StandResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Stand DNS")
    }
}

#[async_trait::async_trait]
impl Resolve for StandResolver {
    async fn publish(
        &self,
        _: &str,
        _: bool,
        _: u64,
        _: Option<(&dyn SigningKey, SignatureScheme)>,
        _: &[SocketEndpointAddr],
    ) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn lookup(&self, name: &str) -> io::Result<Vec<SocketEndpointAddr>> {
        net::lookup_host(name)
            .await
            .map(|iter| iter.map(SocketEndpointAddr::direct).collect())
    }
}
