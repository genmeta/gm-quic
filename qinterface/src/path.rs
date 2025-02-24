use std::{fmt::Display, net::SocketAddr, ops::Deref};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Direct {
        addr: SocketAddr,
    },
    Relay {
        agent: SocketAddr,
        inner: SocketAddr,
    },
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Direct { addr } => write!(f, "{}", addr),
            Endpoint::Relay { agent, inner } => write!(f, "{} <-> {}", agent, inner),
        }
    }
}

impl Deref for Endpoint {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        match self {
            Endpoint::Direct { addr } => addr,
            Endpoint::Relay { inner, .. } => inner,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Pathway {
    local: Endpoint,
    remote: Endpoint,
}

impl Display for Pathway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}) -> ({})", self.local, self.remote)
    }
}

impl Pathway {
    #[inline]
    pub fn new(local: Endpoint, remote: Endpoint) -> Self {
        Self { local, remote }
    }

    #[inline]
    pub fn local(&self) -> Endpoint {
        self.local
    }

    #[inline]
    pub fn remote(&self) -> Endpoint {
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Socket {
    src: SocketAddr,
    dst: SocketAddr,
}

impl Socket {
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
