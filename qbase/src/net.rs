use std::{fmt::Display, net::SocketAddr, ops::Deref};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EndpointAddr {
    Direct {
        addr: SocketAddr,
    },
    Relay {
        agent: SocketAddr,
        outer: SocketAddr,
    },
}

impl Display for EndpointAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndpointAddr::Direct { addr } => write!(f, "Direct({addr}"),
            EndpointAddr::Relay { agent, outer } => write!(f, "Agent({agent}->{outer})"),
        }
    }
}

impl Deref for EndpointAddr {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        match self {
            EndpointAddr::Direct { addr } => addr,
            EndpointAddr::Relay { outer: inner, .. } => inner,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Pathway {
    local: EndpointAddr,
    remote: EndpointAddr,
}

impl Display for Pathway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.local, self.remote)
    }
}

impl Pathway {
    #[inline]
    pub fn new(local: EndpointAddr, remote: EndpointAddr) -> Self {
        Self { local, remote }
    }

    #[inline]
    pub fn local(&self) -> EndpointAddr {
        self.local
    }

    #[inline]
    pub fn remote(&self) -> EndpointAddr {
        self.remote
    }

    #[inline]
    pub fn flip(self) -> Self {
        Self {
            local: self.remote,
            remote: self.local,
        }
    }
}

/// Network way, representing the quadruple of source and destination addresses.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Link {
    src: SocketAddr,
    dst: SocketAddr,
}

impl Display for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}

impl Link {
    #[inline]
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        Self { src, dst }
    }

    #[inline]
    pub fn src(&self) -> SocketAddr {
        self.src
    }

    #[inline]
    pub fn dst(&self) -> SocketAddr {
        self.dst
    }
}
