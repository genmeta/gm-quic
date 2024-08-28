use std::{
    future::Future,
    io,
    net::SocketAddr,
    sync::{Arc, LazyLock, Mutex},
    task::{Poll, Waker},
};

use bytes::BytesMut;
use dashmap::DashMap;
use qbase::{
    cid::ConnectionId,
    packet::{
        header::GetDcid, long, DataHeader, Packet, PacketReader, RetryHeader,
        VersionNegotiationHeader,
    },
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

static LISTENER: LazyLock<Listener> = LazyLock::new(Listener::new);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConnKey {
    Client(ConnectionId),
    Server(ConnectionId),
}

#[derive(Debug, Clone)]
pub struct QuicConnection {
    key: ConnKey,
    inner: ArcConnection,
}

impl QuicConnection {
    pub fn recv_version_negotiation(&self, _vn: &VersionNegotiationHeader) {
        // self.inner.recv_version_negotiation(vn);
    }

    pub fn recv_retry_packet(&self, retry: &RetryHeader, pathway: Pathway, usc: ArcUsc) {
        self.inner.recv_retry_packet(retry, pathway, usc);
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

pub fn get_usc(bind_addr: &SocketAddr) -> ArcUsc {
    let recv_task = |usc: ArcUsc, bind_addr: SocketAddr| {
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
                    // TODO: dcid 长度和生成时的长度一致
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
                                    conn.recv_retry_packet(&retry, pathway, usc.clone());
                                    conn.update_path_recv_time(pathway);
                                } else {
                                    log::error!("No connection found for Retry packet");
                                }
                            }
                            Packet::Data(packet) => {
                                let dcid = packet.header.get_dcid();
                                if !ROUTER.contains_key(dcid)
                                    && matches!(
                                        packet.header,
                                        DataHeader::Long(long::DataHeader::Initial(_))
                                            | DataHeader::Long(long::DataHeader::ZeroRtt(_))
                                    )
                                {
                                    LISTENER.try_accept(bind_addr, *dcid);
                                }
                                match CONNECTIONS
                                    .get(&ConnKey::Client(*dcid))
                                    .or_else(|| CONNECTIONS.get(&ConnKey::Server(*dcid)))
                                {
                                    Some(conn) => conn.update_path_recv_time(pathway),
                                    None => log::error!("No connection found for Data packet"),
                                }
                                log::debug!(
                                    "Recv Data packet: {:?} pathway: {:?}",
                                    packet,
                                    pathway
                                );
                                ROUTER.recv_packet_via_pathway(packet, pathway, &usc.clone());
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

type ConnCreator = Box<dyn Fn(ConnectionId) -> QuicConnection + Send + Sync>;

struct Listener {
    creators: DashMap<SocketAddr, ConnCreator>,
    acceptor: Acceptor,
}

impl Listener {
    fn new() -> Self {
        Self {
            creators: DashMap::new(),
            acceptor: Acceptor::new(),
        }
    }

    fn listen(&self, bind_addr: SocketAddr, creator: ConnCreator) -> io::Result<()> {
        if self.creators.contains_key(&bind_addr) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Address already in use",
            ));
        }
        let _ = get_usc(&bind_addr);
        self.creators.insert(bind_addr, creator);
        Ok(())
    }

    fn try_accept(&self, bind_addr: SocketAddr, dcid: ConnectionId) {
        let ret = self.creators.get(&bind_addr).map(|creator| creator(dcid));
        if let Some(conn) = ret {
            self.acceptor.accept((conn, bind_addr));
        }
    }

    fn unregister(&self, bind_addr: &SocketAddr) {
        self.creators.remove(bind_addr);
    }

    fn accept(&self) -> Acceptor {
        self.acceptor.clone()
    }
}

#[derive(Clone)]
struct Acceptor(
    Arc<Mutex<Option<(QuicConnection, SocketAddr)>>>,
    Arc<Mutex<Option<Waker>>>,
);

impl Acceptor {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(None)), Arc::new(Mutex::new(None)))
    }

    fn accept(&self, value: (QuicConnection, SocketAddr)) {
        *self.0.lock().unwrap() = Some(value);
        if let Some(waker) = self.1.lock().unwrap().take() {
            waker.wake();
        }
    }
}

impl Future for Acceptor {
    type Output = (QuicConnection, SocketAddr);

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(value) = this.0.lock().unwrap().take() {
            Poll::Ready(value)
        } else {
            this.1 = Arc::new(Mutex::new(Some(cx.waker().clone())));
            Poll::Pending
        }
    }
}
