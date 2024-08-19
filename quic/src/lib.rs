use std::{
    net::SocketAddr,
    sync::{LazyLock, Mutex},
};

use dashmap::DashMap;
use qbase::{
    cid::ConnectionId,
    packet::{RetryHeader, VersionNegotiationHeader},
};
use qconnection::connection::ArcConnection;
use qudp::ArcUsc;

pub mod client;
pub mod server;

pub use client::QuicClient;
pub use server::QuicServer;

/// 全局的usc注册管理，用于查找已有的usc，key是绑定的本地地址，包括v4和v6的地址
static _USC_REGISTRY: LazyLock<DashMap<SocketAddr, ArcUsc>> = LazyLock::new(DashMap::new);
/// 全局的QuicConnection注册管理，用于查找已有的QuicConnection，key是初期的Pathway
/// 包括被动接收的连接和主动发起的连接
static CONNECTIONS: LazyLock<Mutex<DashMap<ConnKey, QuicConnection>>> =
    LazyLock::new(|| Mutex::new(DashMap::new()));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConnKey {
    Client(ConnectionId),
    _Server(ConnectionId),
}

#[derive(Debug, Clone)]
pub struct QuicConnection {
    key: ConnKey,
    _inner: ArcConnection,
}

impl QuicConnection {
    pub fn recv_version_negotiation(&self, _vn: &VersionNegotiationHeader) {
        // self.inner.recv_version_negotiation(vn);
    }

    pub fn recv_retry_packet(&self, _retry: &RetryHeader) {
        // self.inner.recv_retry_packet(retry);
    }
}

impl Drop for QuicConnection {
    fn drop(&mut self) {
        CONNECTIONS.lock().unwrap().remove(&self.key);
    }
}

#[cfg(test)]
mod tests {}
