use std::{fmt::Display, net::SocketAddr};

use bytes::BufMut;
use nom::number::streaming::be_u8;
use serde::{Deserialize, Serialize};

use crate::{
    frame::EncodeSize,
    net::{
        Family,
        addr::{BoundAddr, EndpointAddr, SocketEndpointAddr},
        be_socket_addr,
    },
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pathway<E = EndpointAddr> {
    local: E,
    remote: E,
}

impl<E> Pathway<E> {
    #[inline]
    pub fn new(local: E, remote: E) -> Self {
        Self { local, remote }
    }

    #[inline]
    pub fn local(&self) -> E
    where
        E: Clone,
    {
        self.local.clone()
    }

    #[inline]
    pub fn remote(&self) -> E
    where
        E: Clone,
    {
        self.remote.clone()
    }

    #[inline]
    pub fn map<E1>(self, mut f: impl FnMut(E) -> E1) -> Pathway<E1> {
        Pathway {
            local: f(self.local),
            remote: f(self.remote),
        }
    }

    #[inline]
    pub fn flip(self) -> Self {
        Self {
            local: self.remote,
            remote: self.local,
        }
    }
}

impl From<Pathway<SocketEndpointAddr>> for Pathway<EndpointAddr> {
    fn from(value: Pathway<SocketEndpointAddr>) -> Self {
        Pathway::new(
            EndpointAddr::Socket(value.local),
            EndpointAddr::Socket(value.remote),
        )
    }
}

impl TryInto<Pathway<SocketEndpointAddr>> for Pathway<EndpointAddr> {
    type Error = std::io::Error;

    fn try_into(self) -> Result<Pathway<SocketEndpointAddr>, Self::Error> {
        match (self.local, self.remote) {
            (EndpointAddr::Socket(local), EndpointAddr::Socket(remote)) => {
                Ok(Pathway::new(local, remote))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid socket endpoint address type",
            )),
        }
    }
}

impl<E: Display> Display for Pathway<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}---{}", self.local, self.remote)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Link<A = BoundAddr> {
    src: A,
    dst: A,
}

impl<A: Display> Display for Link<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}<->{}", self.src, self.dst)
    }
}

pub fn be_link(input: &[u8]) -> nom::IResult<&[u8], Link<SocketAddr>> {
    let (remain, family) = be_u8(input)?;
    let family = match family {
        0 => Family::V4,
        1 => Family::V6,
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Alt,
            )));
        }
    };
    let (remain, src) = be_socket_addr(remain, family)?;
    let (remain, dst) = be_socket_addr(remain, family)?;
    Ok((remain, Link::<SocketAddr> { src, dst }))
}

pub trait WriteLink {
    fn put_link(&mut self, link: &Link<SocketAddr>);
}

impl<T: BufMut> WriteLink for T {
    fn put_link(&mut self, link: &Link<SocketAddr>) {
        use crate::net::WriteSocketAddr;
        self.put_u8(link.src().is_ipv6() as u8);
        self.put_socket_addr(&link.src);
        self.put_socket_addr(&link.dst);
    }
}

impl From<Link<SocketAddr>> for Link<BoundAddr> {
    fn from(value: Link<SocketAddr>) -> Self {
        Self {
            src: BoundAddr::from(value.src),
            dst: BoundAddr::from(value.dst),
        }
    }
}

impl TryInto<Link<SocketAddr>> for Link<BoundAddr> {
    type Error = std::io::Error;

    fn try_into(self) -> Result<Link<SocketAddr>, Self::Error> {
        match (self.src, self.dst) {
            (BoundAddr::Internet(src), BoundAddr::Internet(dst)) => Ok(Link::new(src, dst)),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid socket address type",
            )),
        }
    }
}

impl EncodeSize for Link<SocketAddr> {
    fn max_encoding_size(&self) -> usize {
        1 + self.src.max_encoding_size() + self.dst.max_encoding_size()
    }

    fn encoding_size(&self) -> usize {
        1 + self.src.encoding_size() + self.dst.encoding_size()
    }
}

impl<A> Link<A> {
    #[inline]
    pub fn new(src: A, dst: A) -> Self {
        Self { src, dst }
    }

    #[inline]
    pub fn src(&self) -> A
    where
        A: Clone,
    {
        self.src.clone()
    }

    #[inline]
    pub fn dst(&self) -> A
    where
        A: Clone,
    {
        self.dst.clone()
    }

    #[inline]
    pub fn map<A1>(self, mut f: impl FnMut(A) -> A1) -> Link<A1> {
        Link {
            src: f(self.src),
            dst: f(self.dst),
        }
    }

    #[inline]
    pub fn flip(self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
        }
    }
}

impl<A, E: From<A>> From<Link<A>> for Pathway<E> {
    fn from(link: Link<A>) -> Self {
        Pathway::new(E::from(link.src), E::from(link.dst))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    pathway: Pathway,
    link: Link,
    ttl: u8,
    ecn: Option<u8>,
    seg_size: u16,
}

impl PacketHeader {
    pub fn new(pathway: Pathway, link: Link, ttl: u8, ecn: Option<u8>, seg_size: u16) -> Self {
        Self {
            pathway,
            link,
            ttl,
            ecn,
            seg_size,
        }
    }

    /// Create a new empty packet header for receive packets.
    pub fn empty() -> Self {
        let src = SocketAddr::from(([0, 0, 0, 0], 0));
        let dst = SocketAddr::from(([0, 0, 0, 0], 0));
        let link = Link::new(BoundAddr::from(src), BoundAddr::from(dst));
        Self::new(link.into(), link, 0, None, 0)
    }

    pub fn pathway(&self) -> Pathway {
        self.pathway
    }

    pub fn link(&self) -> Link {
        self.link
    }

    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    pub fn ecn(&self) -> Option<u8> {
        self.ecn
    }

    pub fn seg_size(&self) -> u16 {
        self.seg_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_addr_from_str() {
        // Test direct format
        let addr = "127.0.0.1:8080".parse::<SocketEndpointAddr>().unwrap();
        assert!(matches!(addr, SocketEndpointAddr::Direct { .. }));

        // Test agent format
        let addr = "127.0.0.1:8080-192.168.1.1:9000"
            .parse::<SocketEndpointAddr>()
            .unwrap();
        assert!(matches!(addr, SocketEndpointAddr::Agent { .. }));

        // Test with whitespace
        let addr = "  127.0.0.1:8080  -  192.168.1.1:9000  "
            .parse::<SocketEndpointAddr>()
            .unwrap();
        assert!(matches!(addr, SocketEndpointAddr::Agent { .. }));

        // Test invalid format
        assert!("invalid".parse::<SocketEndpointAddr>().is_err());
    }
}
