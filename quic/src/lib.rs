use std::{io, net::SocketAddr, sync::LazyLock};

use bytes::BytesMut;
use dashmap::DashMap;
use deref_derive::Deref;
use qbase::{
    cid::ConnectionId,
    packet::{header::GetDcid, Packet, PacketReader, RetryHeader, VersionNegotiationHeader},
};
use qconnection::{
    connection::ArcConnection,
    path::Pathway,
    router::Router,
    usc::{ArcUsc, USCRegisty},
};

pub mod client;
pub mod server;

pub use client::QuicClient;
pub use server::QuicServer;

/// 全局的QuicConnection注册管理，用于查找已有的QuicConnection，key是初期的Pathway
/// 包括被动接收的连接和主动发起的连接
static CONNECTIONS: LazyLock<DashMap<ConnKey, QuicConnection>> = LazyLock::new(DashMap::new);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConnKey {
    Client(ConnectionId),
    Server(ConnectionId),
}

#[derive(Debug, Clone, Deref)]
pub struct QuicConnection {
    _key: ConnKey,
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
        // TODO: remove global connection entry
        // QuicConnection: Clone，only the last clone can remove the entry
        // CONNECTIONS.remove(&self.key);
    }
}

pub fn get_or_create_usc(bind_addr: &SocketAddr) -> io::Result<ArcUsc> {
    let recv_task = |usc: ArcUsc| async move {
        let mut receiver = usc.receiver();
        while let Ok(msg_count) = receiver.recv().await {
            for (hdr, buf) in core::iter::zip(&receiver.headers, &receiver.iovecs).take(msg_count) {
                let data: BytesMut = buf[0..hdr.seg_size as usize].into();
                let pathway = Pathway::Direct {
                    local: hdr.dst,
                    remote: hdr.src,
                };

                let reader = PacketReader::new(data, 8);
                for pkt in reader.flatten() {
                    accpet_packet(pkt, pathway, &usc);
                }
            }
        }
    };

    let usc = USCRegisty::get_or_create_usc(*bind_addr, recv_task)?;
    Ok(usc)
}

fn accpet_packet(packet: Packet, pathway: Pathway, usc: &ArcUsc) {
    match packet {
        Packet::Data(packet) => {
            if let Err(packet) = Router::try_to_route_packet_from(packet, pathway, usc) {
                QuicServer::try_to_accept_conn_from(packet, pathway, usc);
            }
        }
        Packet::VN(vn) => {
            let key = ConnKey::Server(*vn.get_dcid());
            if let Some(conn) = CONNECTIONS.get(&key) {
                conn.recv_version_negotiation(&vn);
                conn.update_path_recv_time(pathway);
            } else {
                log::error!("No connection found for VN packet");
            }
        }
        Packet::Retry(retry) => {
            let key = ConnKey::Server(*retry.get_dcid());
            if let Some(conn) = CONNECTIONS.get(&key) {
                conn.recv_retry_packet(&retry);
                conn.update_path_recv_time(pathway);
            } else {
                log::error!("No connection found for Retry packet");
            }
        }
    }
}
