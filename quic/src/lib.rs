use std::{io, net::SocketAddr, sync::LazyLock};

use bytes::BytesMut;
use dashmap::DashMap;
use qbase::{
    cid::ConnectionId,
    packet::{header::GetDcid, Packet, PacketReader},
    sid::StreamId,
};
use qconnection::{
    conn::{ArcConnection, StreamReader, StreamWriter},
    path::Pathway,
    router::Router,
    usc::{ArcUsc, UscRegistry},
};

pub mod client;
pub mod server;
mod util;

pub use client::QuicClient;
pub use qbase;
pub use qconnection;
pub use qrecovery;
pub use qunreliable;
pub use rustls;
pub use server::QuicServer;

/// 全局的QuicConnection注册管理，用于查找已有的QuicConnection，key是初期的Pathway
/// 包括被动接收的连接和主动发起的连接
static CONNECTIONS: LazyLock<DashMap<ConnKey, ArcConnection>> = LazyLock::new(DashMap::new);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ConnKey {
    Client(ConnectionId),
    Server(ConnectionId),
}

#[derive(Debug)]
pub struct QuicConnection {
    key: ConnKey,
    inner: ArcConnection,
}

impl QuicConnection {
    #[inline]
    pub async fn accept_bi_stream(&self) -> io::Result<(StreamId, (StreamReader, StreamWriter))> {
        self.inner.accept_bi_stream().await
    }

    #[inline]
    pub async fn accept_uni_stream(&self) -> io::Result<(StreamId, StreamReader)> {
        self.inner.accept_uni_stream().await
    }

    /// Gracefully closes the connection.
    ///
    /// Same as [`ArcConnection::close`]
    #[inline]
    pub fn close(&self, msg: impl Into<std::borrow::Cow<'static, str>>) {
        self.inner.close(msg)
    }

    #[inline]
    pub fn datagram_reader(&self) -> io::Result<qunreliable::UnreliableReader> {
        self.inner.datagram_reader()
    }

    #[inline]
    pub async fn datagram_writer(&self) -> io::Result<qunreliable::UnreliableWriter> {
        self.inner.datagram_writer().await
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.inner.is_active()
    }

    #[inline]
    pub async fn open_bi_stream(
        &self,
    ) -> io::Result<Option<(StreamId, (StreamReader, StreamWriter))>> {
        self.inner.open_bi_stream().await
    }

    #[inline]
    pub async fn open_uni_stream(&self) -> io::Result<Option<(StreamId, StreamWriter)>> {
        self.inner.open_uni_stream().await
    }
}

impl Drop for QuicConnection {
    fn drop(&mut self) {
        CONNECTIONS.remove(&self.key);
    }
}

async fn usc_recv_task(usc: ArcUsc) {
    let mut receiver = usc.receiver();
    loop {
        let msg_count = match receiver.recv().await {
            Ok(msg_count) => msg_count,
            Err(err) => {
                let addr = usc.local_addr();
                log::error!("Error while receiving datagrams from {} : {:?}", addr, err);
                QuicServer::on_socket_close(addr);
                break;
            }
        };

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
}

fn get_or_create_usc(bind_addr: &SocketAddr) -> io::Result<ArcUsc> {
    let usc = UscRegistry::get_or_create_usc(*bind_addr, usc_recv_task)?;
    Ok(usc)
}

fn create_new_usc(bind_addr: &SocketAddr) -> io::Result<ArcUsc> {
    let usc = UscRegistry::create_new_usc(*bind_addr, usc_recv_task)?;
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
                // conn.recv_version_negotiation(&vn); unimpl
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
