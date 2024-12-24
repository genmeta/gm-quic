use std::{
    convert::Infallible,
    io, net,
    sync::Arc,
    task::{Context, Poll},
};

use dashmap::DashMap;
use qbase::{cid, packet::Packet, util::ArcAsyncDeque};

use super::entry;
use crate::{
    builder, event, router,
    util::{publish, subscribe},
};

#[derive(Clone)]
struct PathWithTasks {
    path: Arc<super::Path>,
    send_task: tokio::task::AbortHandle,
    recv_task: tokio::task::AbortHandle,
    tick_task: tokio::task::AbortHandle,
    validate_task: tokio::task::AbortHandle,
    heartbeat_task: tokio::task::AbortHandle,
}

impl Drop for PathWithTasks {
    fn drop(&mut self) {
        self.send_task.abort();
        self.recv_task.abort();
        self.tick_task.abort();
        self.validate_task.abort();
        self.heartbeat_task.abort();
    }
}

// packet_subscriber(paths <- create_entry <- components(data_space) <- cid_registry) <- router_revoke/registry <- paths, cycle on paths, fk
// packet_subscriber = ConnInterface(distinguish with Paths)
// how to discovery new path passively?
// when receive a packet from new way, deliver the packway
pub struct ConnInterface {
    router_if: Arc<router::QuicProto>,
    new_path: Box<dyn subscribe::Subscribe<super::Pathway, Error = Infallible> + Send + Sync>,
    deques: DashMap<net::SocketAddr, ArcAsyncDeque<Packet>>,
}

impl ConnInterface {
    pub fn new(
        router_if: Arc<router::QuicProto>,
        new_path: Box<dyn subscribe::Subscribe<super::Pathway, Error = Infallible> + Send + Sync>,
    ) -> Self {
        Self {
            router_if,
            new_path,
            deques: DashMap::default(),
        }
    }
}

impl ConnInterface {
    pub(super) fn new_packet(&self, way: super::Pathway) -> Option<bytes::BytesMut> {
        self.router_if.new_packet(way)
    }

    pub(super) async fn send_packet(
        &self,
        pkt: &[u8],
        way: super::Pathway,
        dst: net::SocketAddr,
    ) -> io::Result<()> {
        self.router_if.send(pkt, way, dst).await
    }
}

impl publish::Publish<super::Pathway> for Arc<ConnInterface> {
    type Resource = Packet;

    fn subscribe(&self, pathway: &super::Pathway) {
        self.deques.entry(pathway.src()).or_default();
    }

    fn poll_acquire(
        &self,
        cx: &mut Context,
        pathway: &super::Pathway,
    ) -> Poll<Option<Self::Resource>> {
        let Some(deque) = self.deques.get(&pathway.src()) else {
            return Poll::Ready(None);
        };
        deque.poll_pop(cx)
    }

    fn unsubscribe(&self, pathway: &super::Pathway) {
        if let Some(deque) = self.deques.get(&pathway.src()) {
            deque.close();
        }
    }
}

impl subscribe::Subscribe<(super::Pathway, Packet)> for ConnInterface {
    type Error = Infallible;

    fn deliver(&self, (pathway, pkt): (super::Pathway, Packet)) -> Result<(), Self::Error> {
        let deque = self.deques.entry(pathway.src()).or_insert_with(|| {
            // Passive path discovery
            _ = self.new_path.deliver(pathway);
            ArcAsyncDeque::new()
        });
        deque.push_back(pkt);
        Ok(())
    }
}

type PathCreator = Box<dyn Fn(&Arc<Paths>, super::Pathway) -> PathWithTasks + Send + Sync>;

pub struct Paths {
    paths: DashMap<net::SocketAddr, PathWithTasks>,
    // the logic is complex enough to be a closure
    create_new_path: PathCreator,
    // terminate the connection when all paths are inactive
    event_broker: Arc<event::EventBroker>,
}

impl Paths {
    pub fn new_with(
        conn_if: Arc<ConnInterface>,
        initial_scid: cid::ConnectionId,
        spaces: builder::Spaces,
        components: builder::Components,
        event_broker: Arc<event::EventBroker>,
    ) -> Self {
        let create_packet_entry =
            entry::generator(spaces.clone(), components.clone(), event_broker.clone());
        let create_cc = {
            let initial_tracker = spaces.initial.tracker();
            let handshake_tracker = spaces.handshake.tracker();
            let data_tracker = spaces.data.tracker();
            let handshake = components.handshake.clone();
            move || {
                qcongestion::ArcCC::new(
                    qcongestion::CongestionAlgorithm::Bbr,
                    core::time::Duration::from_millis(100),
                    [
                        Box::new(initial_tracker.clone()),
                        Box::new(handshake_tracker.clone()),
                        Box::new(data_tracker.clone()),
                    ],
                    handshake.clone(),
                )
            }
        };
        let create_burst = move |path: Arc<super::Path>| {
            path.new_burst(
                initial_scid,
                components.cid_registry.remote.apply_dcid(),
                components.flow_ctrl.clone(),
                spaces.clone(),
            )
        };
        let create_path = move |paths: &Arc<Self>, pathway| {
            let path = super::Path {
                way: pathway,
                cc: (create_cc)(),
                anti_amplifier: super::aa::AntiAmplifier::default(),
                last_recv_time: super::alive::LastReceiveTime::new(),
                challenge_sndbuf: Default::default(),
                response_sndbuf: Default::default(),
                response_rcvbuf: Default::default(),
                conn_if: conn_if.clone(),
            };
            let path = Arc::new(path);

            let on_failed = {
                let paths = paths.clone();
                move || paths.del_path(pathway)
            };

            let burst = (create_burst)(path.clone());
            let send_task = burst.begin_sending(on_failed.clone()).abort_handle();

            let recv_pipe = path.new_receiving_pipeline((create_packet_entry)());
            let recv_task = recv_pipe.begin_recving(on_failed.clone()).abort_handle();

            let tick_task = path.begin_tick().abort_handle();

            let validate_task = path.begin_validation(on_failed.clone()).abort_handle();

            let heartbeat = path.new_heartbeat();
            let heartbeat_task = heartbeat.begin_keeping_alive(on_failed).abort_handle();

            PathWithTasks {
                path,
                send_task,
                recv_task,
                tick_task,
                validate_task,
                heartbeat_task,
            }
        };
        Self {
            paths: DashMap::new(),
            create_new_path: Box::new(create_path),
            event_broker,
        }
    }

    pub fn add_path(self: &Arc<Self>, pathway: super::Pathway) -> Arc<super::Path> {
        let path_entry = self
            .paths
            .entry(pathway.src())
            .or_insert_with(|| (self.create_new_path)(self, pathway));
        path_entry.path.clone()
    }

    pub fn del_path(&self, pathway: super::Pathway) {
        self.paths.remove(&pathway.src());
        if self.paths.is_empty() {
            use subscribe::Subscribe;
            let kind = qbase::error::ErrorKind::NoViablePath;
            let error = qbase::error::Error::with_default_fty(kind, "no viable path");
            let event = event::ConnEvent::TransportError(error);
            _ = self.event_broker.deliver(event)
        }
    }
}
