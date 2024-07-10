use std::{
    collections::HashSet,
    sync::{atomic::AtomicUsize, Arc},
};

use dashmap::DashMap;
use qbase::{
    cid::ConnectionId,
    packet::{header::GetDcid, SpacePacket},
    token::ResetToken,
};
use tokio::sync::mpsc;

use crate::{
    connection::{ArcConnectionHandle, ConnectionInternalId},
    ReceiveProtectedPacket,
};

struct ConnectionResources {
    connection_ids: HashSet<ConnectionId>,
    reset_tokens: HashSet<ResetToken>,
}

#[derive(Default)]
pub struct Endpoint {
    connection_internal_id: AtomicUsize,
    // 尚未实现连接迁移
    connections: Arc<DashMap<ConnectionId, ArcConnectionHandle>>,
    // 某条连接的对端的无状态重置令牌
    reset_tokens: Arc<DashMap<ResetToken, ArcConnectionHandle>>,
    // 一个反向索引表，用于清理连接
    reverse_map: Arc<DashMap<ConnectionInternalId, ConnectionResources>>,
    // 新连接的监听器
    // listener: Listener,
}

impl Endpoint {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_internal_id(&self) -> ConnectionInternalId {
        ConnectionInternalId::new(
            self.connection_internal_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        )
    }

    // 通过管道传递更好/直接操作DashMap更好？
    pub fn spawn_handle_retire_local_connection_id(&self) -> mpsc::UnboundedSender<ConnectionId> {
        let (retire_tx, mut retire_rx) = mpsc::unbounded_channel();
        tokio::spawn({
            let connections = self.connections.clone();
            let resources = self.reverse_map.clone();
            async move {
                while let Some(cid) = retire_rx.recv().await {
                    let conn = connections.remove(&cid);
                    if let Some((_, conn)) = conn {
                        resources
                            .get_mut(&conn.internal_id)
                            .unwrap()
                            .connection_ids
                            .remove(&cid);
                    }
                }
            }
        });

        retire_tx
    }

    pub fn spawn_handle_new_local_connection_id(
        &self,
    ) -> mpsc::UnboundedSender<(ConnectionId, ArcConnectionHandle)> {
        let (conn_tx, mut conn_rx) =
            mpsc::unbounded_channel::<(ConnectionId, ArcConnectionHandle)>();
        tokio::spawn({
            let connections = self.connections.clone();
            let resources = self.reverse_map.clone();
            async move {
                while let Some((cid, conn)) = conn_rx.recv().await {
                    let internal_id = conn.internal_id;
                    connections.insert(cid, conn);
                    resources
                        .get_mut(&internal_id)
                        .unwrap()
                        .connection_ids
                        .insert(cid);
                }
            }
        });

        conn_tx
    }

    pub fn spawn_handle_recv_reomote_reset_token(
        &self,
    ) -> mpsc::UnboundedSender<(ResetToken, ArcConnectionHandle)> {
        let (token_tx, mut token_rx) =
            mpsc::unbounded_channel::<(ResetToken, ArcConnectionHandle)>();
        tokio::spawn({
            let reset_tokens = self.reset_tokens.clone();
            let resources = self.reverse_map.clone();
            async move {
                while let Some((token, conn)) = token_rx.recv().await {
                    let internal_id = conn.internal_id;
                    reset_tokens.insert(token, conn);
                    resources
                        .get_mut(&internal_id)
                        .unwrap()
                        .reset_tokens
                        .insert(token);
                }
            }
        });

        token_tx
    }

    pub fn spawn_handle_retire_remote_reset_token(&self) -> mpsc::UnboundedSender<ResetToken> {
        let (token_tx, mut token_rx) = mpsc::unbounded_channel();
        tokio::spawn({
            let reset_tokens = self.reset_tokens.clone();
            let resources = self.reverse_map.clone();
            async move {
                while let Some(token) = token_rx.recv().await {
                    let conn = reset_tokens.remove(&token);
                    if let Some((_, conn)) = conn {
                        resources
                            .get_mut(&conn.internal_id)
                            .unwrap()
                            .reset_tokens
                            .remove(&token);
                    }
                }
            }
        });

        token_tx
    }

    pub fn spawn_handle_clean_connection(&self) -> mpsc::UnboundedSender<ConnectionInternalId> {
        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();
        tokio::spawn({
            let connections = self.connections.clone();
            let reset_tokens = self.reset_tokens.clone();
            let resources = self.reverse_map.clone();
            async move {
                while let Some(conn) = conn_rx.recv().await {
                    if let Some((_conn, resources)) = resources.remove(&conn) {
                        for cid in resources.connection_ids {
                            connections.remove(&cid);
                        }
                        for token in resources.reset_tokens {
                            reset_tokens.remove(&token);
                        }
                    }
                }
            }
        });

        conn_tx
    }
}

impl ReceiveProtectedPacket for Endpoint {
    fn receive_protected_packet(&mut self, protected_packet: SpacePacket) {
        let dcid = protected_packet.get_dcid();
        if let Some(_conn) = self.connections.get_mut(dcid) {
            // let _ = conn.receive_protected_packet(protected_packet);
        } else {
            match protected_packet {
                SpacePacket::Initial(_packet) => {
                    // TODO: 创建新连接，并塞给Listener
                }
                _other => {
                    // just ignore
                }
            }
        }
    }
}
