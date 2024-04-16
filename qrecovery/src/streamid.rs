/**
 * QUIC有4种流类型，对应着4个流ID空间，分别是：
 * | 低2位 | 流类型 ｜
 * | 0x00 | 客户端创建的双向流 |
 * | 0x01 | 服务端创建的双向流 |
 * | 0x02 | 客户端创建的单向流 |
 * | 0x03 | 服务端创建的单向流 |
 *
 * 低2位，恰好构成一个大小为4的数组的索引，所以可以用数组来表示流类型的StreamId状态。
 * 每个QUIC连接都维护着一个这样的状态。
 *
 * 一个QUIC连接，同时只能拥有一个角色，对端对应着另外一个角色。
 * 需要注意的是，同一主机的QUIC连接的角色并非一成不变的，比如客户端可以变成服务端。
 *
 * 一个流ID是一个62比特的整数（0~2^62-1），这是为了便于VarInt编码。
 * 低2位又是类型，所以每一个类型的流ID总共有2^60个。
 */
use std::{fmt, ops};

/// ## Example
/// ```
/// use qrecovery::streamid::Role;
///
/// let local = Role::Client;
/// let peer = !local;
/// let is_client = matches!(local, Role::Client); // true
/// let is_server = matches!(peer, Role::Server); // true
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Role {
    /// The initiator of a connection
    Client = 0,
    /// The acceptor of a connection
    Server = 1,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match *self {
            Self::Client => "client",
            Self::Server => "server",
        })
    }
}

impl ops::Not for Role {
    type Output = Self;
    fn not(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Dir {
    /// Data flows in both directions
    Bi = 0,
    /// Data flows only from the stream's initiator
    Uni = 2,
}

impl fmt::Display for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match *self {
            Self::Bi => "bidirectional",
            Self::Uni => "unidirectional",
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StreamId(u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} stream {}", self.role(), self.dir(), self.id())
    }
}

/// StreamId没有构建的入口，它只能从每个QUIC连接维护的StreamId状态中取得；或者从对方的数据包中解析出来。
impl StreamId {
    const MAX_STREAM_ID: u64 = (u64::MAX >> 2) - 1;

    pub fn role(&self) -> Role {
        if self.0 & 0x1 == 0 {
            Role::Client
        } else {
            Role::Server
        }
    }

    pub fn dir(&self) -> Dir {
        if self.0 & 2 == 0 {
            Dir::Bi
        } else {
            Dir::Uni
        }
    }

    pub fn id(&self) -> u64 {
        self.0 >> 2
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 4)
    }

    pub fn inc(&mut self) {
        self.0 += 4;
    }

    pub fn iter(&self) -> StreamIdIter {
        StreamIdIter(self.0)
    }
}

// TODO: 从VarInt变成StreamId

pub struct StreamIdIter(u64);

impl Iterator for StreamIdIter {
    type Item = StreamId;

    fn next(&mut self) -> Option<Self::Item> {
        self.0 += 4;
        if self.0 > StreamId::MAX_STREAM_ID {
            None
        } else {
            Some(StreamId(self.0))
        }
    }
}

/// 每个QUIC连接维护着4个流ID，分别对应着4种流类型。
pub struct StreamIds([StreamId; 4]);

impl Default for StreamIds {
    fn default() -> Self {
        Self([StreamId(0), StreamId(1), StreamId(2), StreamId(3)])
    }
}

impl StreamIds {
    pub fn get(&self, role: Role, dir: Dir) -> StreamId {
        self.0[(role as usize) | (dir as usize)]
    }

    pub fn get_mut(&mut self, role: Role, dir: Dir) -> &mut StreamId {
        &mut self.0[(role as usize) | (dir as usize)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_id() {
        let mut stream_ids = StreamIds::default();
        assert_eq!(stream_ids.get(Role::Client, Dir::Bi).0, 0);
        assert_eq!(stream_ids.get(Role::Client, Dir::Uni).0, 2);
        assert_eq!(stream_ids.get(Role::Server, Dir::Bi).0, 1);
        assert_eq!(stream_ids.get(Role::Server, Dir::Uni).0, 3);
        stream_ids.get_mut(Role::Client, Dir::Bi).inc();
        assert_eq!(stream_ids.get(Role::Client, Dir::Bi).0, 4);
        assert_eq!(stream_ids.get(Role::Client, Dir::Uni).0, 2);
        assert_eq!(stream_ids.get(Role::Server, Dir::Bi).0, 1);
        assert_eq!(stream_ids.get(Role::Server, Dir::Uni).0, 3);
    }

    #[test]
    fn test_stream_id_iter() {
        let mut stream_ids = StreamIds::default();
        let mut iter = stream_ids.get(Role::Client, Dir::Bi).iter();
        assert_eq!(iter.next().unwrap().0, 4);
        assert_eq!(iter.next().unwrap().0, 8);
        assert_eq!(iter.next().unwrap().0, 12);
        assert_eq!(iter.next().unwrap().0, 16);

        let mut sid = stream_ids.get_mut(Role::Client, Dir::Bi);
        assert_eq!(sid.0, 0);
        sid.0 = StreamId::MAX_STREAM_ID - 3;
        let mut iter = sid.iter();
        assert_eq!(iter.next(), None);
    }
}
