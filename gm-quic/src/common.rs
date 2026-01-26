use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use futures::{Stream, StreamExt, stream};
use qconnection::{
    prelude::{SocketEndpointAddr, handy},
    qinterface::{
        BindInterface, Interface,
        bind_uri::BindUri,
        component::{
            Components,
            alive::RebindOnNetworkChangedComponent,
            location::{Locations, LocationsComponent},
            route::{QuicRouter, QuicRouterComponent},
        },
        device::Devices,
        io::ProductIO,
        manager::InterfaceManager,
    },
    qtraversal::{
        nat::{client::StunClientsComponent, router::StunRouterComponent},
        route::{ForwardersComponent, ReceiveAndDeliverPacketComponent},
    },
};

use crate::qtraversal::resolver::{Resolve, StandResolver};

#[derive(Clone)]
pub struct Network {
    pub resolver: Arc<dyn Resolve + Send + Sync>,
    pub devices: &'static Devices,
    pub iface_factory: Arc<dyn ProductIO>,
    pub iface_manager: Arc<InterfaceManager>,
    pub quic_router: Arc<QuicRouter>,
    pub stun_server: Option<Arc<str>>,
    pub locations: Arc<Locations>,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            resolver: Arc::new(StandResolver),
            devices: Devices::global(),
            iface_factory: Arc::new(handy::DEFAULT_IO_FACTORY),
            iface_manager: InterfaceManager::global().clone(),
            quic_router: QuicRouter::global().clone(),
            stun_server: None,
            locations: Arc::new(Locations::new()),
        }
    }
}

impl Network {
    async fn lookup_agents(&self, stun_server: &str) -> Option<Vec<SocketAddr>> {
        let stream = self.resolver.lookup(stun_server);
        let agents: Vec<SocketAddr> = stream
            .filter_map(|res| async move {
                match res {
                    Ok((_, SocketEndpointAddr::Direct { addr })) => Some(addr),
                    _ => None,
                }
            })
            .collect()
            .await;
        (!agents.is_empty()).then_some(agents)
    }

    fn init_iface_components(
        &self,
        bind_iface: &BindInterface,
        stun_agent: Option<(Arc<str>, &[SocketAddr])>,
    ) {
        bind_iface.with_components_mut(move |components: &mut Components, iface: &Interface| {
            // rebind interface on network changed
            components.init_with(|| RebindOnNetworkChangedComponent::new(iface, self.devices));
            // quic packet router
            let quic_router = components
                .init_with(|| QuicRouterComponent::new(self.quic_router.clone()))
                .router();

            let locations = components
                .init_with(|| LocationsComponent::new(iface.downgrade(), self.locations.clone()))
                .clone();

            match stun_agent {
                // stun enabled:
                Some((stun_server, stun_agents)) => {
                    // initial stun router
                    let stun_router = components
                        .init_with(|| StunRouterComponent::new(iface.downgrade()))
                        .router();
                    // initial stun clients
                    let clients = components
                        .init_with(|| {
                            StunClientsComponent::new(
                                iface.downgrade(),
                                stun_router.clone(),
                                self.resolver.clone(),
                                stun_server,
                                stun_agents.to_vec(),
                                Some(locations.clone()),
                            )
                        })
                        .clone();
                    // initial forwarder
                    let relay = bind_iface
                        .bind_uri()
                        .relay()
                        .and_then(|r| r.parse::<SocketAddr>().ok());

                    let forwarder = if let Some(relay) = relay {
                        components
                            .init_with(|| ForwardersComponent::new_server(relay))
                            .forwarder()
                    } else {
                        components
                            .init_with(|| ForwardersComponent::new_client(clients))
                            .forwarder()
                    };

                    // initial receive and deliver packet component(quic, stun and forwarder)
                    components.init_with(|| {
                        ReceiveAndDeliverPacketComponent::builder(iface.downgrade())
                            .quic_router(quic_router)
                            .stun_router(stun_router)
                            .forwarder(forwarder)
                            .init()
                    });
                }
                // no stun: receive and deliver quic only
                None => {
                    components.init_with(|| {
                        ReceiveAndDeliverPacketComponent::builder(iface.downgrade())
                            .quic_router(quic_router)
                            .init()
                    });
                }
            };
        });
    }

    pub async fn bind(&self, bind_uri: BindUri) -> BindInterface {
        let stun_server = if let Some(server) = bind_uri.stun_server() {
            Some(Arc::from(server))
        } else if let Some("false") = bind_uri.prop(BindUri::STUN_PROP).as_deref() {
            None
        } else {
            self.stun_server.clone()
        };

        let stun_agents = if let Some(server) = &stun_server {
            self.lookup_agents(server).await.unwrap_or_default()
        } else {
            Vec::new()
        };

        let factory = self.iface_factory.clone();
        let bind_iface = self.iface_manager.bind(bind_uri, factory).await;
        self.init_iface_components(
            &bind_iface,
            stun_server.map(|s| (s, stun_agents.as_slice())),
        );
        bind_iface
    }

    pub async fn bind_many(
        &self,
        bind_uris: impl IntoIterator<Item = impl Into<BindUri>>,
    ) -> impl Stream<Item = BindInterface> {
        let this = self.clone();
        let cache = std::sync::Arc::new(std::sync::Mutex::new(
            HashMap::<Arc<str>, Vec<SocketAddr>>::new(),
        ));
        stream::iter(bind_uris).then(move |bind_uri| {
            let this = this.clone();
            let cache = cache.clone();
            async move {
                let bind_uri = bind_uri.into();
                let stun_server = if let Some(server) = bind_uri.stun_server() {
                    Some(Arc::from(server))
                } else if let Some("false") = bind_uri.prop(BindUri::STUN_PROP).as_deref() {
                    None
                } else {
                    this.stun_server.clone()
                };

                let stun_agents = if let Some(stun_server) = &stun_server {
                    let cached = {
                        let cache = cache.lock().unwrap();
                        cache.get(stun_server).cloned()
                    };

                    if let Some(agents) = cached {
                        agents
                    } else {
                        let agents = this.lookup_agents(stun_server).await.unwrap_or_default();
                        cache
                            .lock()
                            .unwrap()
                            .insert(stun_server.clone(), agents.clone());
                        agents
                    }
                } else {
                    Vec::new()
                };

                let factory = this.iface_factory.clone();
                let bind_iface = this.iface_manager.bind(bind_uri, factory).await;
                this.init_iface_components(
                    &bind_iface,
                    stun_server.map(|s| (s, stun_agents.as_slice())),
                );
                bind_iface
            }
        })
    }
}
