use std::{hash::Hash, net::SocketAddr};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct RelayAddr {
    pub agent: SocketAddr, // 代理人
    pub addr: SocketAddr,
}

/// 无论哪种Pathway，socket都必须绑定local地址
#[derive(Debug, Eq, Clone, Copy)]
pub enum Pathway {
    Direct {
        local: SocketAddr,
        remote: SocketAddr,
    },
    Relay {
        local: RelayAddr,
        remote: RelayAddr,
    },
}

impl Pathway {
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            Pathway::Direct { local, .. } => *local,
            Pathway::Relay { local, .. } => local.addr,
        }
    }

    pub fn remote_addr(&self) -> SocketAddr {
        match self {
            Pathway::Direct { remote, .. } => *remote,
            Pathway::Relay { remote, .. } => remote.addr,
        }
    }

    pub fn dst_addr(&self) -> SocketAddr {
        match self {
            Pathway::Direct { remote, .. } => *remote,
            Pathway::Relay { remote, .. } => remote.agent,
        }
    }

    pub fn filp(self) -> Self {
        match self {
            Pathway::Direct { local, remote } => Pathway::Direct {
                local: remote,
                remote: local,
            },
            Pathway::Relay { local, remote } => Pathway::Relay {
                local: remote,
                remote: local,
            },
        }
    }
}

impl PartialEq for Pathway {
    fn eq(&self, other: &Self) -> bool {
        let match_local = |l: &SocketAddr, r: &SocketAddr| {
            if l.ip().is_unspecified() | r.ip().is_unspecified() {
                l.is_ipv4() == r.is_ipv4() && l.port() == r.port()
            } else {
                l == r
            }
        };
        match (self, other) {
            (
                Self::Direct {
                    local: l_local,
                    remote: l_remote,
                },
                Self::Direct {
                    local: r_local,
                    remote: r_remote,
                },
            ) => l_remote == r_remote && match_local(l_local, r_local),
            (
                Self::Relay {
                    local: l_local,
                    remote: l_remote,
                },
                Self::Relay {
                    local: r_local,
                    remote: r_remote,
                },
            ) => {
                l_remote == r_remote
                    && match_local(&l_local.addr, &r_local.addr)
                    && l_local.agent == r_local.agent
            }
            _ => false,
        }
    }
}

impl Hash for Pathway {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn test_normal() {
        let v4addr1: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let v4addr2: SocketAddr = "127.0.0.1:5678".parse().unwrap();
        let v6addr1: SocketAddr = "[::1]:1234".parse().unwrap();

        let direct1 = Pathway::Direct {
            local: v4addr1,
            remote: v4addr2,
        };
        let direct2 = Pathway::Direct {
            local: v4addr1,
            remote: v4addr2,
        };
        let direct3 = Pathway::Direct {
            local: v6addr1,
            remote: v4addr1,
        };
        assert_eq!(direct1, direct2);
        assert_ne!(direct1, direct3);

        let relay1 = RelayAddr {
            addr: v4addr1,
            agent: v4addr2,
        };
        let relay2 = RelayAddr {
            addr: v4addr1,
            agent: v4addr2,
        };
        let relay3 = RelayAddr {
            addr: v6addr1,
            agent: v4addr1,
        };

        assert_eq!(
            Pathway::Relay {
                local: relay1,
                remote: relay2
            },
            Pathway::Relay {
                local: relay1,
                remote: relay2
            }
        );

        assert_ne!(
            Pathway::Relay {
                local: relay1,
                remote: relay2
            },
            Pathway::Relay {
                local: relay1,
                remote: relay3
            }
        );
    }

    #[test]
    fn test_unspecified() {
        let v4addr_unspec1: SocketAddr = "0.0.0.0:1234".parse().unwrap();
        let v4addr_unspec2: SocketAddr = "0.0.0.0:5678".parse().unwrap();
        let v4addr1: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let v4addr2: SocketAddr = "127.0.0.1:5678".parse().unwrap();

        let v6addr_unspec1: SocketAddr = "[::]:1234".parse().unwrap();
        let v6addr1: SocketAddr = "[::1]:1234".parse().unwrap();

        assert_ne!(
            Pathway::Direct {
                local: v4addr_unspec1,
                remote: v4addr2,
            },
            Pathway::Direct {
                local: v4addr2,
                remote: v4addr2,
            }
        );

        assert_eq!(
            Pathway::Direct {
                local: v4addr_unspec1,
                remote: v4addr2,
            },
            Pathway::Direct {
                local: v4addr1,
                remote: v4addr2,
            }
        );

        assert_ne!(
            Pathway::Direct {
                local: v4addr_unspec2,
                remote: v4addr2,
            },
            Pathway::Direct {
                local: v6addr1,
                remote: v4addr2,
            }
        );

        assert_eq!(
            Pathway::Direct {
                local: v6addr_unspec1,
                remote: v6addr1
            },
            Pathway::Direct {
                local: v6addr1,
                remote: v6addr1
            }
        );
    }

    #[test]
    fn test_mapped() {
        let v6addr_unspec1: SocketAddr = "[::]:1234".parse().unwrap();
        let v6addr_mapped1: SocketAddr = "[::ffff:127.0.0.1]:1234".parse().unwrap();
        let v6addr_mapped2: SocketAddr = "[::ffff:127.0.0.1]:5678".parse().unwrap();
        let v6addr1: SocketAddr = "[::1]:1234".parse().unwrap();

        // bind v6 unspec, recv from v4
        assert_eq!(
            Pathway::Direct {
                local: v6addr_unspec1,
                remote: v6addr1
            },
            Pathway::Direct {
                local: v6addr_mapped1,
                remote: v6addr1
            }
        );

        // bind v6 addr, recv form v4
        assert_ne!(
            Pathway::Direct {
                local: v6addr1,
                remote: v6addr_mapped2
            },
            Pathway::Direct {
                local: v6addr_mapped1,
                remote: v6addr_mapped2
            }
        )
    }

    #[test]
    fn test_hash() {
        let mut map = HashMap::new();
        let v4addr_unspec1: SocketAddr = "0.0.0.0:1234".parse().unwrap();
        let v4addr1: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let v4addr2: SocketAddr = "127.0.0.1:5678".parse().unwrap();

        let direct1 = Pathway::Direct {
            local: v4addr_unspec1,
            remote: v4addr2,
        };
        let direct2 = Pathway::Direct {
            local: v4addr1,
            remote: v4addr2,
        };

        map.insert(direct1, 1);
        assert_eq!(map.get(&direct2), Some(1).as_ref());
        map.insert(direct2, 2);
        assert_eq!(map.get(&direct1), Some(2).as_ref());
    }
}
