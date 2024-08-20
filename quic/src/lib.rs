use std::{net::SocketAddr, sync::LazyLock};

use bytes::BytesMut;
use dashmap::DashMap;
use qbase::{
    cid::{ConnectionId, MAX_CID_SIZE},
    packet::{header::GetDcid, Packet, PacketReader, RetryHeader, VersionNegotiationHeader},
};
use qconnection::{connection::ArcConnection, path::Pathway, router::ROUTER};
use qudp::ArcUsc;

pub mod client;
pub mod server;

pub use client::QuicClient;
pub use server::QuicServer;

/// 全局的usc注册管理，用于查找已有的usc，key是绑定的本地地址，包括v4和v6的地址
static USC_REGISTRY: LazyLock<DashMap<SocketAddr, ArcUsc>> = LazyLock::new(DashMap::new);
/// 全局的QuicConnection注册管理，用于查找已有的QuicConnection，key是初期的Pathway
/// 包括被动接收的连接和主动发起的连接
static CONNECTIONS: LazyLock<DashMap<ConnKey, QuicConnection>> = LazyLock::new(DashMap::new);

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
        CONNECTIONS.remove(&self.key);
    }
}

pub fn get_usc(bind_addr: &SocketAddr) -> ArcUsc {
    let usc = USC_REGISTRY
        .entry(*bind_addr)
        .or_insert_with(|| ArcUsc::new(*bind_addr).expect("Failed to create UdpSocket controller"))
        .value()
        .clone();

    let mut receiver = usc.receiver();
    tokio::spawn(async move {
        while let Ok(msg_count) = (&mut receiver).await {
            for (hdr, buf) in receiver
                .headers
                .iter()
                .zip(receiver.iovecs.iter())
                .take(msg_count)
            {
                let data: BytesMut = buf[0..hdr.seg_size as usize].into();
                let pathway = Pathway::Direct {
                    local: hdr.dst,
                    remote: hdr.src,
                };
                let reader = PacketReader::new(data, MAX_CID_SIZE);
                for pkt in reader.flatten() {
                    match pkt {
                        Packet::VN(vn) => {
                            let key = ConnKey::Client(*vn.get_dcid());
                            if let Some(conn) = CONNECTIONS.get(&key) {
                                conn.recv_version_negotiation(&vn);
                            } else {
                                log::error!("No connection found for VN packet");
                            }
                        }
                        Packet::Retry(retry) => {
                            let key = ConnKey::Client(*retry.get_dcid());
                            if let Some(conn) = CONNECTIONS.get(&key) {
                                conn.recv_retry_packet(&retry);
                            } else {
                                log::error!("No connection found for Retry packet");
                            }
                        }
                        Packet::Data(packet) => {
                            ROUTER.recv_packet_via_pathway(packet, pathway, &receiver.usc.clone());
                        }
                    }
                }
            }
        }
    });
    usc
}

#[cfg(test)]
mod tests {}
