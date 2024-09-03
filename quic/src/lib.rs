use std::{
    net::SocketAddr,
    sync::{LazyLock, RwLock},
};

use bytes::BytesMut;
use dashmap::DashMap;
use deref_derive::Deref;
use qbase::{
    cid::ConnectionId,
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

/// 理应全局只有一个server
static SERVER: LazyLock<RwLock<Option<QuicServer>>> = LazyLock::new(|| RwLock::new(None));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConnKey {
    Client(ConnectionId),
    Server(ConnectionId),
}

#[derive(Debug, Clone, Deref)]
pub struct QuicConnection {
    key: ConnKey,
    #[deref]
    inner: ArcConnection,
}

impl QuicConnection {
    pub fn recv_version_negotiation(&self, _vn: &VersionNegotiationHeader) {
        // self.inner.recv_version_negotiation(vn);
    }

    pub fn recv_retry_packet(&self, retry: &RetryHeader) {
        self.inner.recv_retry_packet(retry);
    }

    pub fn update_path_recv_time(&self, pathway: Pathway) {
        self.inner.update_path_recv_time(pathway);
    }
}

impl Drop for QuicConnection {
    fn drop(&mut self) {
        CONNECTIONS.remove(&self.key);
    }
}

pub fn get_usc_or_create(bind_addr: &SocketAddr) -> ArcUsc {
    let recv_task = |usc: ArcUsc, _bind_addr: SocketAddr| {
        let mut receive = usc.receive();
        tokio::spawn(async move {
            while let Ok(msg_count) = (&mut receive).await {
                for (hdr, buf) in receive
                    .headers
                    .iter()
                    .zip(receive.iovecs.iter())
                    .take(msg_count)
                {
                    let data: BytesMut = buf[0..hdr.seg_size as usize].into();
                    let pathway = Pathway::Direct {
                        local: hdr.dst,
                        remote: hdr.src,
                    };

                    let reader = PacketReader::new(data, 8);
                    for pkt in reader.flatten() {
                        match pkt {
                            Packet::VN(vn) => {
                                let key = ConnKey::Client(*vn.get_dcid());
                                if let Some(conn) = CONNECTIONS.get(&key) {
                                    conn.recv_version_negotiation(&vn);
                                    conn.update_path_recv_time(pathway);
                                } else {
                                    log::error!("No connection found for VN packet");
                                }
                            }
                            Packet::Retry(retry) => {
                                let key = ConnKey::Client(*retry.get_dcid());
                                if let Some(conn) = CONNECTIONS.get(&key) {
                                    conn.recv_retry_packet(&retry);
                                    conn.update_path_recv_time(pathway);
                                } else {
                                    log::error!("No connection found for Retry packet");
                                }
                            }
                            Packet::Data(packet) => {
                                if let Some(packet) =
                                    ROUTER.recv_packet_via_pathway(packet, pathway, &usc)
                                {
                                    if let Some(server) = SERVER.read().unwrap().as_ref() {
                                        server.recv_unmatched_packet(packet, pathway, &usc);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    };

    let usc = USC_REGISTRY
        .entry(*bind_addr)
        .or_insert_with(|| {
            let usc = ArcUsc::new(*bind_addr).expect("Failed to create UdpSocket controller");
            recv_task(usc.clone(), *bind_addr);
            usc
        })
        .value()
        .clone();
    usc
}
