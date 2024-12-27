use std::{
    io,
    ops::DerefMut,
    sync::{Arc, RwLock},
};

use qbase::{cid, flow, param, sid};
use qrecovery::{recv, reliable, send, streams};

use super::router::RouterRegistry;
use crate::{builder, dying, event, path, util::subscribe};

pub type ArcLocalCids = cid::ArcLocalCids<RouterRegistry<reliable::ArcReliableFrameDeque>>;
pub type ArcRemoteCids = cid::ArcRemoteCids<reliable::ArcReliableFrameDeque>;
pub type CidRegistry = cid::Registry<ArcLocalCids, ArcRemoteCids>;

pub type FlowController = flow::FlowController<reliable::ArcReliableFrameDeque>;
pub type Credit<'a> = flow::Credit<'a, reliable::ArcReliableFrameDeque>;

pub type DataStreams = streams::DataStreams<reliable::ArcReliableFrameDeque>;
pub type StreamWriter = send::Writer<streams::Ext<reliable::ArcReliableFrameDeque>>;
pub type StreamReader = recv::Reader<streams::Ext<reliable::ArcReliableFrameDeque>>;

pub type Handshake = qbase::handshake::Handshake<reliable::ArcReliableFrameDeque>;

type ConnState = Result<builder::CoreConnection, dying::DyingConnection>;

pub struct Connection {
    inner: RwLock<ConnState>,
    event_broker: event::EventBroker,
}

impl Connection {
    fn migrate_state(&self, migrate: impl FnOnce(ConnState) -> ConnState) {
        let mut write_guard = self.inner.write().unwrap();

        // Safety: the invalid_state will not be accessed
        #[allow(clippy::uninit_assumed_init, invalid_value)]
        let invalid_state = unsafe { ::core::mem::MaybeUninit::uninit().assume_init() };
        let old_state = ::core::mem::replace(write_guard.deref_mut(), invalid_state);
        // Safety: use ptr::write to skip the Drop implementation of the invalid_state
        unsafe {
            ::core::ptr::write(write_guard.deref_mut(), migrate(old_state));
        }
    }

    fn enter_closing(self: &Arc<Self>, error: qbase::error::Error) {
        self.migrate_state(|conn| {
            let event_broker = self.event_broker.clone();
            match conn {
                Ok(core_conn) => {
                    let conn = self.clone();
                    let pto_time = core_conn.paths.max_pto_time();
                    tokio::spawn(async move {
                        tokio::time::sleep(pto_time * 3).await;
                        conn.enter_closed();
                    });
                    Err(dying::DyingConnection {
                        state: core_conn.entry_closing(&error, event_broker).into(),
                        error,
                    })
                }
                Err(_) => conn,
            }
        })
    }

    fn enter_draining(self: &Arc<Self>, error: qbase::error::Error) {
        self.migrate_state(|conn| match conn {
            Ok(core_conn) => {
                let conn = self.clone();
                let pto_time = core_conn.paths.max_pto_time();
                tokio::spawn(async move {
                    tokio::time::sleep(pto_time * 3).await;
                    conn.enter_closed();
                });
                Err(dying::DyingConnection {
                    state: core_conn.enter_draining(&error).into(),
                    error,
                })
            }
            Err(dying::DyingConnection {
                state: dying::DyingState::Closing(closing_conn),
                error,
            }) => Err(dying::DyingConnection {
                state: closing_conn.enter_draining().into(),
                error,
            }),
            _ => conn,
        })
    }

    #[doc(alias = "die")]
    fn enter_closed(&self) {
        self.migrate_state(|conn| match conn {
            Ok(_) => unreachable!(),
            Err(dying::DyingConnection {
                state: dying::DyingState::Closing(closing_conn),
                error,
            }) => Err(dying::DyingConnection {
                state: closing_conn.enter_closed().into(),
                error,
            }),
            Err(dying::DyingConnection {
                state: dying::DyingState::Draining(draining_conn),
                error,
            }) => Err(dying::DyingConnection {
                state: draining_conn.enter_closed().into(),
                error,
            }),
            _ => conn,
        });
    }

    fn launch_event_handler(conn: Arc<Self>, mut events: event::ConnEvents) {
        tokio::spawn(async move {
            use futures::StreamExt;
            while let Some(event) = events.next().await {
                match event {
                    event::ConnEvent::ApplicationClose => return,
                    event::ConnEvent::TransportError(error) => conn.enter_closing(error),
                    event::ConnEvent::ReceivedCcf(ccf) => conn.enter_draining(ccf.into()),
                }
            }
        });
    }

    pub fn run_with(
        core_conn_builder: impl FnOnce(event::EventBroker) -> builder::CoreConnection,
    ) -> Arc<Self> {
        let (event_broker, events) = event::pipeline();
        let conn = core_conn_builder(event_broker.clone());
        let arc_conn = Arc::new(Self {
            inner: RwLock::new(Ok(conn)),
            event_broker,
        });
        Self::launch_event_handler(arc_conn.clone(), events);
        arc_conn
    }

    pub fn close(self: &Arc<Self>, msg: impl Into<std::borrow::Cow<'static, str>>) {
        use subscribe::Subscribe;
        _ = self
            .event_broker
            .deliver(event::ConnEvent::ApplicationClose);
        let error =
            qbase::error::Error::with_default_fty(qbase::error::ErrorKind::Application, msg);
        self.enter_closing(error);
    }

    fn map_core_conn<T>(&self, map: impl FnOnce(&builder::CoreConnection) -> T) -> io::Result<T> {
        self.inner
            .read()
            .unwrap()
            .as_ref()
            .map_err(|dying| dying.error.clone().into())
            .map(map)
    }

    pub async fn open_bi_stream(
        &self,
    ) -> io::Result<Option<(sid::StreamId, (StreamReader, StreamWriter))>> {
        use subscribe::Subscribe;
        let (params, streams) = self.map_core_conn(|core_conn| {
            (
                core_conn.components.parameters.clone(),
                core_conn.spaces.data.streams().clone(),
            )
        })?;
        let param::Pair { remote, .. } = params.await?;
        let result = streams
            .open_bi(remote.initial_max_stream_data_bidi_remote().into())
            .await
            .inspect_err(|e| _ = self.event_broker.deliver(e.clone().into()));
        Ok(result?)
    }

    pub async fn open_uni_stream(&self) -> io::Result<Option<(sid::StreamId, StreamWriter)>> {
        use subscribe::Subscribe;
        let (params, streams) = self.map_core_conn(|core_conn| {
            (
                core_conn.components.parameters.clone(),
                core_conn.spaces.data.streams().clone(),
            )
        })?;
        let param::Pair { remote, .. } = params.await?;
        let result = streams
            .open_uni(remote.initial_max_stream_data_uni().into())
            .await
            .inspect_err(|e| _ = self.event_broker.deliver(e.clone().into()));
        Ok(result?)
    }

    pub async fn accept_bi_stream(
        &self,
    ) -> io::Result<Option<(sid::StreamId, (StreamReader, StreamWriter))>> {
        use subscribe::Subscribe;
        let (params, streams) = self.map_core_conn(|core_conn| {
            (
                core_conn.components.parameters.clone(),
                core_conn.spaces.data.streams().clone(),
            )
        })?;
        let param::Pair { remote, .. } = params.await?;
        let result = streams
            .accept_bi(remote.initial_max_stream_data_bidi_local().into())
            .await
            .inspect_err(|e| _ = self.event_broker.deliver(e.clone().into()));
        Ok(Some(result?))
    }

    pub async fn accept_uni_stream(&self) -> io::Result<Option<(sid::StreamId, StreamReader)>> {
        use subscribe::Subscribe;
        let (streams,) =
            self.map_core_conn(|core_conn| (core_conn.spaces.data.streams().clone(),))?;
        let result = streams
            .accept_uni()
            .await
            .inspect_err(|e| _ = self.event_broker.deliver(e.clone().into()));
        Ok(Some(result?))
    }

    pub fn unreliable_reader(&self) -> io::Result<qunreliable::UnreliableReader> {
        self.map_core_conn(|core_conn| core_conn.spaces.data.datagrams().reader())?
    }

    pub async fn unreliable_writer(&self) -> io::Result<qunreliable::UnreliableWriter> {
        let (params, datagrams) = self.map_core_conn(|core_conn| {
            (
                core_conn.components.parameters.clone(),
                core_conn.spaces.data.datagrams().clone(),
            )
        })?;
        let param::Pair { remote, .. } = params.await?;
        datagrams.writer(remote.max_datagram_frame_size().into())
    }

    pub fn add_path(&self, pathway: path::Pathway) -> io::Result<()> {
        self.map_core_conn(|core_conn| _ = core_conn.paths.add_path(pathway))
    }

    pub fn del_path(&self, pathway: path::Pathway) -> io::Result<()> {
        self.map_core_conn(|core_conn| core_conn.paths.del_path(pathway))
    }
}
