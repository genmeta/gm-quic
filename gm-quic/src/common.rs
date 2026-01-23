use std::{net::SocketAddr, sync::Arc};

use futures::{Stream, StreamExt, stream};
use qconnection::{
    prelude::{SocketEndpointAddr, handy},
    qdns::{Resolve, StandResolver},
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

#[derive(Clone)]
pub struct Network {
    pub resolver: Arc<dyn Resolve + Send + Sync>,
    pub devices: &'static Devices,
    pub iface_factory: Arc<dyn ProductIO>,
    pub iface_manager: Arc<InterfaceManager>,
    pub quic_router: Arc<QuicRouter>,
    pub stun_server: Option<Arc<str>>,
    pub locations: Option<Arc<Locations>>,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            resolver: Arc::new(StandResolver::new()),
            devices: Devices::global(),
            iface_factory: Arc::new(handy::DEFAULT_IO_FACTORY),
            iface_manager: InterfaceManager::global().clone(),
            quic_router: QuicRouter::global().clone(),
            stun_server: None,
            locations: None,
        }
    }
}

impl Network {
    async fn lookup_agents(&self) -> Option<Vec<SocketAddr>> {
        self.resolver
            .lookup(self.stun_server.as_ref()?)
            .await
            .map(|agents| {
                agents
                    .into_iter()
                    .filter_map(|agent| match agent {
                        SocketEndpointAddr::Direct { addr } => Some(addr),
                        SocketEndpointAddr::Agent { .. } => None,
                    })
                    .collect::<Vec<_>>()
            })
            .ok()
    }

    fn init_iface_components(&self, bind_iface: &BindInterface, stun_agents: &[SocketAddr]) {
        bind_iface.with_components_mut(move |components: &mut Components, iface: &Interface| {
            // rebind interface on network changed
            components.init_with(|| RebindOnNetworkChangedComponent::new(iface, self.devices));
            // quic packet router
            let quic_router = components
                .init_with(|| QuicRouterComponent::new(self.quic_router.clone()))
                .router();

            let locations = self.locations.clone().map(|locations| {
                components
                    .init_with(|| LocationsComponent::new(iface.downgrade(), locations.clone()))
                    .clone()
            });

            match self.stun_server.clone() {
                // stun enabled:
                Some(stun_server) => {
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
                                locations,
                            )
                        })
                        .clone();
                    // initial forwarder
                    let forwarder = components
                        .init_with(|| ForwardersComponent::new_client(clients))
                        .forwarder();
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
        let stun_agetns = self.lookup_agents().await.unwrap_or_default();
        let factory = self.iface_factory.clone();
        let bind_iface = self.iface_manager.bind(bind_uri, factory).await;
        self.init_iface_components(&bind_iface, &stun_agetns);
        bind_iface
    }

    pub async fn bind_many(
        &self,
        bind_uris: impl IntoIterator<Item = impl Into<BindUri>>,
    ) -> impl Stream<Item = BindInterface> {
        let stun_agents = self.lookup_agents().await.unwrap_or_default();

        stream::iter(bind_uris)
            .then(async |bind_uri| {
                self.iface_manager
                    .bind(bind_uri.into(), self.iface_factory.clone())
                    .await
            })
            .inspect(move |bind_iface| self.init_iface_components(bind_iface, &stun_agents))
    }
}
