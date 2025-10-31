use std::io;

use async_trait::async_trait;
pub use gmdns::mdns::Mdns as MdnsResolver;
use qbase::net::route::SocketEndpointAddr;
use rustls::{SignatureScheme, sign::SigningKey};

use crate::{Resolve, to_endpoint_addr};

#[async_trait]
impl Resolve for MdnsResolver {
    async fn publish(
        &self,
        name: &str,
        _is_main: bool,
        _sequence: u64,
        _key: Option<(&dyn SigningKey, SignatureScheme)>,
        addresses: &[SocketEndpointAddr],
    ) -> io::Result<()> {
        let addresses: Vec<_> = addresses
            .iter()
            .filter(|addr| matches!(addr, SocketEndpointAddr::Direct { .. }))
            .map(|addr| addr.addr())
            .collect();
        self.insert_host(name.to_string(), addresses);
        Ok(())
    }

    async fn lookup(&self, name: &str) -> io::Result<Vec<SocketEndpointAddr>> {
        self.query(name.to_string())
            .await
            .map(|addr_list| addr_list.iter().map(to_endpoint_addr).collect::<Vec<_>>())
    }
}
