use std::{net::SocketAddr, sync::Arc};

use futures::{Stream, StreamExt, stream};
use qconnection::{
    prelude::{AddrKind, EndpointAddr, SocketEndpointAddr, handy},
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
use qresolve::{Family, Resolve, SystemResolver};

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
            resolver: Arc::new(SystemResolver),
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
    /// 只取第一个可用的 STUN agent 即返回，后续由 StunClientsComponent 自动补充到 MIN_AGENTS
    async fn lookup_first_agent(
        &self,
        stun_server: &str,
        family: Option<Family>,
    ) -> Option<Vec<SocketAddr>> {
        let mut stream = self.resolver.lookup(stun_server).await.ok()?;
        while let Some((_, EndpointAddr::Socket(SocketEndpointAddr::Direct { addr }))) =
            stream.next().await
        {
            if match family {
                None => true,
                Some(Family::V4) => addr.is_ipv4(),
                Some(Family::V6) => addr.is_ipv6(),
            } {
                tracing::trace!("resolved first stun agent for {}: {}", stun_server, addr);
                return Some(vec![addr]);
            }
        }
        None
    }

    fn init_iface_components(
        &self,
        bind_iface: &BindInterface,
        stun_agent: Option<(Arc<str>, Vec<SocketAddr>)>,
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
                    // initial stun clients (后续会自动补充到 MIN_AGENTS)
                    let clients = components
                        .init_with(|| {
                            StunClientsComponent::new(
                                iface.downgrade(),
                                stun_router.clone(),
                                self.resolver.clone(),
                                stun_server,
                                stun_agents,
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

        let family = match bind_uri.addr_kind() {
            AddrKind::Internet(family) => Some(family),
            _ => None,
        };

        let stun_agents = match &stun_server {
            Some(server) => self
                .lookup_first_agent(server.as_ref(), family)
                .await
                .unwrap_or_default(),
            None => vec![],
        };

        let factory = self.iface_factory.clone();
        let bind_iface = self.iface_manager.bind(bind_uri, factory).await;
        self.init_iface_components(&bind_iface, stun_server.map(|s| (s, stun_agents)));

        bind_iface
    }

    pub async fn bind_many(
        &self,
        bind_uris: impl IntoIterator<Item = impl Into<BindUri>>,
    ) -> impl Stream<Item = BindInterface> {
        stream::iter(bind_uris).then(async |bind_uri| self.bind(bind_uri.into()).await)
    }
}
