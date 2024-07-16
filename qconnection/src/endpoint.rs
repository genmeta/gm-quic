use std::{
    io::{self, IoSliceMut},
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use dashmap::DashMap;
use futures::{ready, Future};
use qbase::{
    cid::{ConnectionId, MAX_CID_SIZE},
    packet::{header::GetDcid, Packet, PacketReader, SpacePacket},
    token::ResetToken,
};
use qudp::{ArcUsc, PacketHeader, BATCH_SIZE};

use crate::{connection::ArcConnectionHandle, path::Pathway, ReceiveProtectedPacket};

#[derive(Clone)]
pub struct Endpoint {
    connections: Arc<DashMap<ConnectionId, ArcConnectionHandle>>,
    // 某条连接的对端的无状态重置令牌
    reset_tokens: Arc<DashMap<ResetToken, ArcConnectionHandle>>,
    // TODO: 管理多个 usc
    /// `UdpSocketController` manages a UDP socket with additional configurations,
    /// providing asynchronous I/O operations, TTL management, and support for GSO and GRO.
    usc: ArcUsc,
    // 新连接的监听器
    // listener: Listener,
}

impl Endpoint {
    pub fn new(usc: ArcUsc) -> Self {
        let ep = Self {
            connections: Arc::new(DashMap::new()),
            reset_tokens: Arc::new(DashMap::new()),
            usc,
        };

        let mut rcvd = RcvdState::new(ep.clone());

        tokio::spawn(async move {
            loop {
                let state = &mut rcvd;
                if let Err(e) = state.await {
                    log::error!("io error: {}", e);
                    // todo: notify application, close udp
                }
            }
        });

        ep
    }
}

impl ReceiveProtectedPacket for Endpoint {
    fn receive_protected_packet(&self, protected_packet: SpacePacket, pathway: Pathway) {
        let dcid = protected_packet.get_dcid();
        if let Some(conn) = self.connections.get(dcid) {
            conn.recv_protected_pkt_via(protected_packet, &self.usc, pathway);
        } else if let SpacePacket::Initial(_packet) = protected_packet {
            // TODO: 创建新连接，并塞给Listener
        }

        // In other cases, discard it directly
    }
}

struct RcvdState {
    iovecs: Vec<Vec<u8>>,
    headers: Vec<PacketHeader>,
    ep: Endpoint,
}

impl RcvdState {
    fn new(ep: Endpoint) -> Self {
        RcvdState {
            ep,
            iovecs: (0..BATCH_SIZE)
                .map(|_| [0u8; 1500].to_vec())
                .collect::<Vec<_>>(),
            headers: (0..BATCH_SIZE)
                .map(|_| PacketHeader::default())
                .collect::<Vec<_>>(),
        }
    }
}

impl Future for RcvdState {
    type Output = io::Result<usize>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let state = self.get_mut();
        let usc = &state.ep.usc;
        let mut bufs = state
            .iovecs
            .iter_mut()
            .map(|b| {
                b.clear();
                IoSliceMut::new(b)
            })
            .collect::<Vec<_>>();

        let ret = ready!(usc.poll_recv(&mut bufs, &mut state.headers, cx));

        match ret {
            Ok(msg_count) => {
                for (hdr, buf) in state.headers.iter().zip(bufs.iter()).take(msg_count) {
                    let data: BytesMut = buf[0..hdr.seg_size as usize].into();
                    let pathway = Pathway::Direct {
                        local: hdr.dst,
                        remote: hdr.src,
                    };
                    let reader = PacketReader::new(data, MAX_CID_SIZE);
                    for packet in reader.flatten() {
                        match packet {
                            Packet::VN(_) => {
                                todo!()
                            }
                            Packet::Retry(_) => todo!(),
                            Packet::Space(space_pkt) => {
                                state
                                    .ep
                                    .receive_protected_packet(space_pkt, pathway.clone());
                            }
                        }
                    }
                }
                Poll::Ready(Ok(msg_count))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}
