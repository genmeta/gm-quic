use std::{
    fmt::{Debug, Display},
    io,
    net::SocketAddr,
};

use gmdns::MdnsEndpoint;
use qbase::net::route::SocketEndpointAddr;

mod resolvers;

pub use gmdns::parser::record::*;
pub use resolvers::*;
use rustls::{SignatureScheme, sign::SigningKey};
use thiserror::Error;

pub const HTTP_DNS_SERVER: &str = "https://dns.genmeta.net/";
pub const MDNS_SERVICE: &str = "_genmeta.local";

#[async_trait::async_trait]
pub trait Resolve: Display + Debug {
    async fn publish(
        &self,
        name: &str,
        is_main: bool,
        sequence: u64,
        key: Option<(&dyn SigningKey, SignatureScheme)>,
        addresses: &[SocketEndpointAddr],
    ) -> io::Result<()>;

    async fn lookup(&self, name: &str) -> io::Result<Vec<SocketEndpointAddr>>;
}

#[derive(Debug, Error)]
pub enum UnsupportedEndpointAddressType {
    #[error("Outer and agent address must be both IPv4 or both IPv6")]
    IncompleteOuterAndAgent,
    #[error("Signing error: {message}")]
    SignError { message: String },
}

pub(crate) fn to_signed_mdns_ep(
    endpoint: SocketEndpointAddr,
    is_main: bool,
    sequence: u64,
    signer: Option<(&dyn SigningKey, SignatureScheme)>,
) -> Result<MdnsEndpoint, UnsupportedEndpointAddressType> {
    let mut ep = match endpoint {
        SocketEndpointAddr::Direct { addr } => match addr {
            SocketAddr::V4(addr) => MdnsEndpoint::direct_v4(addr),
            SocketAddr::V6(addr) => MdnsEndpoint::direct_v6(addr),
        },
        SocketEndpointAddr::Agent { agent, outer } => match (agent, outer) {
            (SocketAddr::V4(agent), SocketAddr::V4(outer)) => MdnsEndpoint::relay_v4(outer, agent),
            (SocketAddr::V6(agent), SocketAddr::V6(outer)) => MdnsEndpoint::relay_v6(outer, agent),
            _ => return Err(UnsupportedEndpointAddressType::IncompleteOuterAndAgent),
        },
    };

    ep.set_main(is_main);
    ep.set_sequence(sequence);

    if let Some((key, scheme)) = signer {
        ep.sign_with(key, scheme)
            .map_err(|e| UnsupportedEndpointAddressType::SignError {
                message: e.to_string(),
            })?;
    }

    Ok(ep)
}

pub(crate) fn to_endpoint_addr(mdns_ep: &MdnsEndpoint) -> SocketEndpointAddr {
    if let Some(agent) = mdns_ep.agent {
        SocketEndpointAddr::with_agent(agent, mdns_ep.primary)
    } else {
        SocketEndpointAddr::direct(mdns_ep.primary)
    }
}
