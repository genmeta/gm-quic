use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::Arc,
};

use qbase::net::route::Link;

use super::UdpSocket;
use crate::{
    dock::Dock,
    protocol::stun::{Request, StunError, StunProtocol},
};

pub struct EphemeralSocket {
    udp: Arc<UdpSocket>,
    dock: Arc<Dock>,
    remove_on_drop: bool,
}

impl EphemeralSocket {
    pub fn bind(dock: Arc<Dock>, addr: SocketAddr) -> io::Result<Self> {
        let udp = Arc::new(UdpSocket::bind(addr)?);
        dock.add(udp.clone())?;
        Ok(Self {
            udp,
            dock,
            remove_on_drop: true,
        })
    }

    pub fn udp_socket(&self) -> &Arc<UdpSocket> {
        &self.udp
    }

    pub async fn outer_addr(
        &self,
        stun: &Arc<StunProtocol>,
        agent: SocketAddr,
    ) -> Result<SocketAddr, StunError> {
        let mut transaction = stun.new_transaction();
        let link = Link::new(self.udp.local_addr()?, agent);
        let (_, response) = transaction.request(link, Request::default()).await?;
        Ok(response.map_addr()?)
    }

    pub async fn send(&self, packets: &[IoSlice<'_>], link: Link) -> io::Result<usize> {
        let segment_size = packets.first().map_or(0, |packet| packet.len());
        let line = qbase::net::route::Line::new(
            link,
            qbase::net::route::Line::DEFAULT_TTL,
            None,
            segment_size.min(u16::MAX as usize) as u16,
        );
        self.udp.send(packets, line).await
    }

    pub fn into_udp_socket(mut self) -> Arc<UdpSocket> {
        self.remove_on_drop = false;
        self.udp.clone()
    }
}

impl Drop for EphemeralSocket {
    fn drop(&mut self) {
        if self.remove_on_drop {
            self.dock.remove(&self.udp);
        }
    }
}
