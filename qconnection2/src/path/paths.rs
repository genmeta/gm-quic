use std::{net, sync::Arc};

use dashmap::DashMap;
use qbase::{cid, sid};

use super::entry;
use crate::{builder, event, router, util::subscribe};

struct PathContext {
    path: Arc<super::Path>,
    validate_task: Option<tokio::task::AbortHandle>,
    send_task: tokio::task::AbortHandle,
    recv_task: tokio::task::AbortHandle,
    tick_task: tokio::task::AbortHandle,
    heartbeat_task: tokio::task::AbortHandle,
}

impl Drop for PathContext {
    fn drop(&mut self) {
        if let Some(validata_task) = self.validate_task.as_ref() {
            validata_task.abort();
        }
        self.send_task.abort();
        self.recv_task.abort();
        self.tick_task.abort();
        self.heartbeat_task.abort();
    }
}

// used to hide `PathWithTasks` struct
#[allow(clippy::type_complexity)]
pub struct PathCreator(Box<dyn Fn(&Arc<Paths>, super::Pathway) -> PathContext + Send + Sync>);

pub struct Paths {
    paths: DashMap<net::SocketAddr, PathContext>,
    // the logic is complex enough to be a closure
    path_creator: PathCreator,
    // terminate the connection when all paths are inactive
    event_broker: event::EventBroker,
}

impl super::Path {
    pub fn creator(
        conn_if: Arc<router::ConnInterface>,
        initial_scid: cid::ConnectionId,
        spaces: builder::Spaces,
        components: builder::Components,
        event_broker: event::EventBroker,
    ) -> PathCreator {
        let create_packet_entry =
            entry::generator(spaces.clone(), components.clone(), event_broker.clone());
        let create_cc = {
            let initial_tracker = Box::new(spaces.initial.tracker());
            let handshake_tracker = Box::new(spaces.handshake.tracker());
            let data_tracker = Box::new(spaces.data.tracker());
            let handshake = components.handshake.clone();
            move || {
                qcongestion::ArcCC::new(
                    qcongestion::CongestionAlgorithm::Bbr,
                    ::core::time::Duration::from_millis(100),
                    [
                        initial_tracker.clone(),
                        handshake_tracker.clone(),
                        data_tracker.clone(),
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
        PathCreator(Box::new(move |paths: &Arc<Paths>, pathway| {
            let path = super::Path {
                way: pathway,
                cc: (create_cc)(),
                anti_amplifier: super::aa::AntiAmplifier::default(),
                last_recv_time: super::alive::LastReceiveTime::now(),
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

            let validate_task = if components.handshake.is_handshake_done() {
                Some(path.begin_validation(on_failed.clone()).abort_handle())
            } else {
                if components.handshake.role() == sid::Role::Client {
                    path.grant_anti_amplifier();
                }
                None
            };

            let heartbeat = path.new_heartbeat();
            let heartbeat_task = heartbeat.begin_keeping_alive(on_failed).abort_handle();

            PathContext {
                validate_task,
                path,
                send_task,
                recv_task,
                tick_task,
                heartbeat_task,
            }
        }))
    }
}

impl Paths {
    pub fn new_with(path_creator: PathCreator, event_broker: event::EventBroker) -> Self {
        Self {
            paths: DashMap::new(),
            path_creator,
            event_broker,
        }
    }

    pub fn add_path(self: &Arc<Self>, pathway: super::Pathway) -> Arc<super::Path> {
        let path_entry = self
            .paths
            .entry(pathway.src())
            .or_insert_with(|| (self.path_creator.0)(self, pathway));
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

    pub fn on_conn_error(&self, error: &qbase::error::Error) {
        _ = error;
        self.paths.clear();
    }

    pub fn max_pto_time(&self) -> tokio::time::Duration {
        use qcongestion::CongestionControl;
        self.paths
            .iter()
            .map(|entry| entry.value().path.cc.pto_time(qbase::Epoch::Data))
            .max()
            .unwrap_or_default()
    }
}