use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    io,
    sync::{Arc, RwLock, RwLockWriteGuard, Weak},
};

use dashmap::{DashMap, DashSet};
use handy::UdpSocketController;
use qbase::net::address::{AbstractAddr, QuicAddr, ToAbstractAddrs};
use qconnection::builder::*;
use qevent::{
    quic::connectivity::ServerListening,
    telemetry::{Log, handy::NullLogger},
};
use qinterface::util::Channel;
use rustls::{
    ConfigBuilder, ServerConfig as TlsServerConfig, WantsVerifier,
    server::{NoClientAuth, ResolvesServerCert, danger::ClientCertVerifier},
};
use tokio::sync::{
    OwnedSemaphorePermit, Semaphore,
    mpsc::{self},
};

use crate::*;

type TlsServerConfigBuilder<T> = ConfigBuilder<TlsServerConfig, T>;

#[derive(Debug, Default)]
pub struct VirtualHosts(Arc<DashMap<String, Host>>);

impl ResolvesServerCert for VirtualHosts {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.0.get(client_hello.server_name()?).map(|host| {
            Arc::new(rustls::sign::CertifiedKey {
                cert: host.cert_chain.clone(),
                key: host.private_key.clone(),
                ocsp: host.ocsp.clone(),
            })
        })
    }
}

pub struct Host {
    bind_addresses: DashSet<AbstractAddr>,
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: Arc<dyn rustls::sign::SigningKey>,
    ocsp: Option<Vec<u8>>,
}

impl Host {
    /// Start to build a [`Host`].
    ///
    /// Return [`io::Error`] if the certificate chain or private key is invalid / failed to read.
    ///
    /// Note that the validity of the private key will be checked in [`QuicListenersBuilder::add_host`].
    pub fn with_cert_key(
        cert_chain: impl ToCertificate,
        private_key: impl ToPrivateKey,
    ) -> io::Result<HostBuilder> {
        Ok(HostBuilder {
            bind_addresses: HashSet::new(),
            cert_chain: cert_chain.to_certificate(),
            private_key: private_key.to_private_key(),
            ocsp: None,
        })
    }
}

impl Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host")
            .field(
                "bind_interfaces",
                &self
                    .bind_addresses
                    .iter()
                    .map(|e| e.key().clone())
                    .collect::<Vec<_>>(),
            )
            .field("cert_chain", &self.cert_chain)
            .field("private_key", &self.private_key)
            .finish()
    }
}

/// Builder [`Host`] that can be added to the [`QuicListeners`].
///
/// Call [`Host::with_cert_key`] to create a new [`HostBuilder`].
pub struct HostBuilder {
    pub bind_addresses: HashSet<AbstractAddr>,
    pub cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub private_key: rustls::pki_types::PrivateKeyDer<'static>,
    pub ocsp: Option<Vec<u8>>,
}

impl HostBuilder {
    /// Add bind addresses to the host.
    ///
    /// The bind addresses will be bind when [`QuicListenersBuilder::add_host`] is called,
    /// and the host will listen to them when the [`QuicListeners`] is started.
    ///
    /// If you call this multiple times, only the last call will take effect.
    ///
    /// After the [`QuicListeners`] is started, you can also call [`QuicListeners::add_interface`]
    /// to add more interfaces to the host.
    pub fn bind_addresses(mut self, bind_addresses: impl ToAbstractAddrs) -> io::Result<Self> {
        self.bind_addresses = bind_addresses.to_abstract_addrs()?.collect();
        Ok(self)
    }

    pub fn with_ocsp(mut self, ocsp: impl Into<Option<Vec<u8>>>) -> Self {
        self.ocsp = ocsp.into();
        self
    }
}

/// An interface that has been bound to hosts in the [`QuicListeners`].
struct BoundInterface {
    iface: Arc<dyn QuicInterface>,
    hosts: DashSet<String>,
}

impl Debug for BoundInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenedInterface")
            .field("interface", &self.iface.abstract_addr())
            .field("servers", &self.hosts)
            .finish()
    }
}

impl Drop for BoundInterface {
    fn drop(&mut self) {
        crate::proto().del_interface_if(self.iface.abstract_addr(), |iface, _| {
            Arc::ptr_eq(iface, &self.iface) && Arc::strong_count(iface) == 2
        });
    }
}

pub type Incoming = (
    /* server_name: */ String,
    /* connection:  */ Arc<Connection>,
    /* pathway:     */ Pathway,
    /* link:        */ Link,
);

/// The quic listeners that can serving multiple hosts(QuicServer), accept incoming connections.
///
/// To create listeners, you need to use the [`QuicListenersBuilder`] to configure the server, and then call the
/// [`QuicListenersBuilder::listen`] method to start listening.
///
/// [`QuicListenersBuilder`] is uniqueis unique, and only one Listeners can run at the same time.
/// You can call [`QuicListeners::shutdown`], or drop all references to the [`Arc<QuicListeners>`] to stop the listeners.
///
/// You can let the quic Listener serve multiple Hosts by calling [`QuicListenersBuilder::add_host`] multiple times.
/// Each Host only accepts connections from the interface it listens to,
/// and the interfaces listened to by Hosts can overlap.
///
/// Host can be added without binding any interface.
///
/// After the [`QuicListenersBuilder::listen`], you can call [`QuicListeners::add_interface`]
/// to let a Host listen to more interface, and [`QuicListeners::del_interface`] to remove an interface from a Host.
///
/// By calling [`QuicListeners::accept`], you can accept a connection.
/// If the host which the incoming connection is connected is not listening
/// on the interface which received the incoming connection,
/// the connection will be automatically rejected.
///
/// The connection returned by [`QuicListeners::accept`] may not have completed the handshake.
///
pub struct QuicListeners {
    defer_idle_timeout: HeartbeatConfig,
    incomings: Arc<Channel<(Incoming, OwnedSemaphorePermit)>>,
    parameters: ServerParameters,
    stream_strategy_factory: Box<dyn ProductStreamsConcurrencyController>,
    backlog: Arc<Semaphore>,
    logger: Arc<dyn Log + Send + Sync>,
    _supported_versions: Vec<u32>,
    hosts: Arc<DashMap<String, Host>>,
    ifaces: Arc<DashMap<AbstractAddr, BoundInterface>>,
    tls_config: Arc<TlsServerConfig>,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

impl QuicListeners {
    /// Start to build a [`QuicListeners`].
    pub fn builder() -> io::Result<QuicListenersBuilder<TlsServerConfigBuilder<WantsVerifier>>> {
        Self::builder_with_tls(TlsServerConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS13,
        ]))
    }

    /// Start to build a QuicServer with the given tls crypto provider.
    pub fn builder_with_crypto_provieder(
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> io::Result<QuicListenersBuilder<TlsServerConfigBuilder<WantsVerifier>>> {
        Self::builder_with_tls(
            TlsServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        )
    }

    /// Start to build a [`QuicListeners`] with the given TLS configuration.
    ///
    /// This is useful when you want to customize the TLS configuration, or integrate qm-quic with other crates.
    pub fn builder_with_tls<T>(tls_config: T) -> io::Result<QuicListenersBuilder<T>> {
        let global_guard = QuicListeners::global()
            .write()
            .expect("QuicListeners global lock");
        if let Some(server) = global_guard.upgrade() {
            if !server.incomings.is_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "A QuicServer is already running, please shutdown it first.",
                ));
            }
        }
        Ok(QuicListenersBuilder {
            global_guard,
            supported_versions: Vec::with_capacity(2),
            quic_iface_factory: Box::new(UdpSocketController::bind),
            defer_idle_timeout: HeartbeatConfig::default(),
            parameters: ServerParameters::default(),
            hosts: Arc::new(DashMap::new()),
            ifaces: Arc::new(DashMap::new()),
            tls_config,
            stream_strategy_factory: Box::new(ConsistentConcurrency::new),
            logger: None,
            token_provider: None,
        })
    }

    /// Let the host bind to an interface.
    ///
    /// The host must have been added when creating the [`QuicListeners`], otherwise this method will return an error.
    ///
    /// If the added Interface has the same abstract address as an existing Interface but they are different instances,
    /// the old Interface will be replaced, and packets will no longer be accepted on the old Interface.
    pub fn add_interface(
        &self,
        host: impl Into<String>,
        iface: Arc<dyn QuicInterface>,
    ) -> io::Result<()> {
        let host = host.into();
        let new_addr = iface.local_addr()?;
        let Some(host_entry) = self.hosts.get(&host) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Host {host} not exist."),
            ));
        };
        // update or insert the interface
        let listened_interface = match self.ifaces.entry(iface.abstract_addr()) {
            dashmap::Entry::Occupied(mut exist_iface) => {
                // if the interface on the same address is already exist, update if the interface is different
                if !Arc::ptr_eq(&iface, &exist_iface.get().iface) {
                    crate::proto().add_interface(iface.clone());
                    exist_iface.insert(BoundInterface {
                        iface: iface.clone(),
                        hosts: exist_iface.get().hosts.clone(),
                    });
                }
                exist_iface.into_ref()
            }
            dashmap::Entry::Vacant(vacant_entry) => {
                crate::proto().add_interface(iface.clone());
                vacant_entry.insert(BoundInterface {
                    iface: iface.clone(),
                    hosts: DashSet::default(),
                })
            }
        };

        host_entry
            .bind_addresses
            .insert(listened_interface.iface.abstract_addr());
        if listened_interface.hosts.insert(host) {
            qevent::event!(ServerListening { address: new_addr });
        }

        Ok(())
    }

    /// Make a specific Host or all Hosts stop listening on an interface.
    ///
    /// If `host` is not [`None`], only remove the interface for that host, which requires the Host to exist.
    /// If host is [`None`], make all Hosts stop listening on that interface.
    ///
    /// If an Interface is no longer being listened to by any Host, the Interface will be released.
    /// However, a Host can listen on no interfaces.
    ///
    /// Removing an interface that has already been removed will return `Ok(())`.
    pub fn del_interface(
        &self,
        host: Option<impl Into<String>>,
        bind: AbstractAddr,
    ) -> io::Result<()> {
        let dashmap::Entry::Occupied(bind_interface) = self.ifaces.entry(bind.clone()) else {
            return Ok(());
        };
        match host {
            Some(host) => {
                let host = host.into();
                let Some(host_entry) = self.hosts.get_mut(&host) else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Host {host} not exist."),
                    ));
                };
                if host_entry.bind_addresses.remove(&bind).is_none() {
                    return Ok(()); // already removed
                }
                if host_entry.bind_addresses.is_empty() {
                    bind_interface.remove();
                }
            }
            None => {
                let bind_interface = bind_interface.remove();
                for host in bind_interface.hosts.iter() {
                    let host = self.hosts.get_mut(&*host).expect("Host must exist");
                    host.bind_addresses.remove(&bind);
                }
            }
        }
        Ok(())
    }

    /// Gets all hosts of the [`QuicListeners`] and their bound abstract addresses,
    /// as well as the actual addresses corresponding to the abstract addresses.
    ///
    /// If the Interface corresponding to an abstract address doesn't exist or is damaged,
    /// the corresponding actual address will be None.
    pub fn hosts(&self) -> HashMap<String, HashMap<AbstractAddr, Option<QuicAddr>>> {
        self.hosts
            .iter()
            .map(|entry| {
                let addresses = entry
                    .value()
                    .bind_addresses
                    .iter()
                    .map(|addr| {
                        let iface = self.ifaces.get(&addr).expect("Interface must exist");
                        let local_addr = iface.iface.local_addr().ok();
                        (addr.key().clone(), local_addr)
                    })
                    .collect();
                let server_name = entry.key().to_owned();
                (server_name, addresses)
            })
            .collect()
    }

    /// Accept a connection.
    ///
    /// If the host which the incoming connection is connected is not listening
    /// on the interface which received the incoming connection,
    /// the connection will be automatically rejected.
    ///
    /// The number of connections queued is limited by the backlog parameter provided to [`QuicListenersBuilder::listen`].
    /// If the queue is full, new initial packets received by the [`QuicListeners`] may be dropped.
    pub async fn accept(&self) -> io::Result<(String, Arc<Connection>, Pathway, Link)> {
        let no_address_listening = || io::Error::other("Server shutdown");
        self.incomings
            .recv()
            .await
            .ok_or_else(no_address_listening)
            .map(|(i, _)| i)
    }

    /// Close the QuicListeners, stops accepting new connections.
    ///
    /// Connections in the queue (unaccepted connections)will be closed
    pub fn shutdown(&self) {
        if self.incomings.close().is_none() {
            // already closed
            return;
        }

        self.incomings.close();
        self.backlog.close();
    }
}

impl Drop for QuicListeners {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// internal methods
impl QuicListeners {
    fn global() -> &'static RwLock<Weak<QuicListeners>> {
        static LISTENERS: OnceLock<RwLock<Weak<QuicListeners>>> = OnceLock::new();
        LISTENERS.get_or_init(Default::default)
    }

    pub(crate) async fn try_accept_connection(
        iface_addr: AbstractAddr,
        packet: Packet,
        pathway: Pathway,
        link: Link,
    ) {
        let Some(listeners) = Self::global().read().unwrap().upgrade() else {
            return;
        };

        let bound_ifaces = listeners.ifaces.clone();
        if !bound_ifaces.contains_key(&iface_addr) {
            return;
        }

        // Acquire a permit from the backlog semaphore to limit the number of concurrent connections.
        let Ok(premit) = listeners.backlog.clone().acquire_owned().await else {
            return;
        };

        let (client_scid, origin_dcid) = match &packet {
            Packet::Data(data_packet) => match &data_packet.header {
                DataHeader::Long(LongHeader::Initial(hdr)) => (*hdr.scid(), *hdr.dcid()),
                DataHeader::Long(LongHeader::ZeroRtt(hdr)) => (*hdr.scid(), *hdr.dcid()),
                _ => return,
            },
            _ => return,
        };

        if origin_dcid.is_empty() {
            tracing::warn!("Received a packet with empty destination CID, ignoring it");
            return;
        }

        let token_provider = listeners
            .token_provider
            .clone()
            .unwrap_or_else(|| Arc::new(NoopTokenRegistry));

        let (event_broker, mut events) = mpsc::unbounded_channel();

        let connection = Arc::new(
            Connection::with_token_provider(token_provider)
                .with_parameters(listeners.parameters.clone())
                .with_tls_config(listeners.tls_config.clone())
                .with_streams_concurrency_strategy(listeners.stream_strategy_factory.as_ref())
                .with_proto(crate::proto().clone())
                .defer_idle_timeout(listeners.defer_idle_timeout)
                .with_cids(origin_dcid, client_scid)
                .with_qlog(listeners.logger.as_ref())
                .run_with(event_broker),
        );

        tokio::spawn(async move {
            crate::proto()
                .deliver(iface_addr.clone(), packet, pathway, link)
                .await;

            tokio::spawn({
                let connection = connection.clone();
                async move {
                    while let Some(event) = events.recv().await {
                        match event {
                            Event::Handshaked => {}
                            Event::ProbedNewPath(..) => {}
                            Event::PathInactivated(iface_addr, ..) => {
                                crate::proto().try_free_interface(iface_addr);
                            }
                            Event::ApplicationClose => {}
                            Event::Failed(error) => {
                                connection.enter_closing(qbase::error::Error::from(error).into())
                            }
                            Event::Closed(ccf) => connection.enter_draining(ccf),
                            Event::StatelessReset => { /* TOOD: stateless reset */ }
                            Event::Terminated => return,
                        }
                    }
                }
            });

            match connection.server_name().await {
                Ok(server_name) => {
                    if !bound_ifaces
                        .get(&iface_addr)
                        .is_some_and(|iface| iface.hosts.contains(&server_name))
                    {
                        tracing::warn!(
                            role = "server",
                            odcid = format!("{origin_dcid:x}"),
                            "Connection from {} with server name {server_name} is not allowed.",
                            link.dst()
                        );
                        connection.close("", 1);
                        return;
                    }
                    let incoming = (server_name, connection.clone(), pathway, link);
                    if listeners.incomings.send((incoming, premit)).await.is_err() {
                        connection.close("", 1);
                    }
                }
                Err(error) => {
                    tracing::error!(
                        role = "server",
                        odcid = format!("{origin_dcid:x}"),
                        "Failed to accept connection from {}: {error:?}",
                        link.dst()
                    );
                }
            }
        });
    }

    pub(crate) fn on_interface_broken(
        iface_addr: AbstractAddr,
        broken_iface: Weak<dyn QuicInterface>,
        error: io::Error,
    ) {
        let Some(listeners) = Self::global().read().unwrap().upgrade() else {
            return;
        };

        if let Some(listened_interface) = listeners.ifaces.get(&iface_addr) {
            if Weak::ptr_eq(&Arc::downgrade(&listened_interface.iface), &broken_iface) {
                for server_name in listened_interface.hosts.iter() {
                    let server_name = &*server_name;
                    tracing::error!(
                        "Interface {iface_addr} used by {server_name} was closed unexpectedly: {error:?}."
                    );
                }
            }
        };
    }
}

/// The builder for the quic listeners.
pub struct QuicListenersBuilder<T> {
    global_guard: RwLockWriteGuard<'static, Weak<QuicListeners>>,
    supported_versions: Vec<u32>,
    quic_iface_factory: Box<dyn ProductQuicInterface>,
    defer_idle_timeout: HeartbeatConfig,
    parameters: ServerParameters,
    hosts: Arc<DashMap<String, Host>>,
    ifaces: Arc<DashMap<AbstractAddr, BoundInterface>>,
    tls_config: T,
    stream_strategy_factory: Box<dyn ProductStreamsConcurrencyController>,
    logger: Option<Arc<dyn Log + Send + Sync>>,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

impl<T> QuicListenersBuilder<T> {
    /// (WIP)Specify the supported quic versions.
    ///
    /// If you call this multiple times, only the last call will take effect.
    pub fn with_supported_versions(mut self, versions: impl IntoIterator<Item = u32>) -> Self {
        self.supported_versions.clear();
        self.supported_versions.extend(versions);
        self
    }

    /// Specify how server to create and verify the client's Token in [address verification].
    ///
    /// If you call this multiple times, only the last `token_provider` will be used.
    ///
    /// [address verification](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation)
    pub fn with_token_provider(mut self, token_provider: Arc<dyn TokenProvider>) -> Self {
        self.token_provider = Some(token_provider);
        self
    }

    /// Specify the factory which product the streams concurrency strategy controller for the server.
    ///
    /// The streams controller is used to control the concurrency of data streams.
    /// Take a look of [`ControlStreamsConcurrency`] for more information.
    ///
    /// If you call this multiple times, only the last `controller` will be used.
    pub fn with_streams_concurrency_strategy(
        mut self,
        strategy_factory: impl ProductStreamsConcurrencyController + 'static,
    ) -> Self {
        self.stream_strategy_factory = Box::new(strategy_factory);
        self
    }

    /// Provide an option to defer an idle timeout.
    ///
    /// This facility could be used when the application wishes to avoid losing
    /// state that has been associated with an open connection but does not expect
    /// to exchange application data for some time.
    ///
    /// See [Deferring Idle Timeout](https://datatracker.ietf.org/doc/html/rfc9000#name-deferring-idle-timeout)
    /// of [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)
    /// for more information.
    pub fn defer_idle_timeout(mut self, config: HeartbeatConfig) -> Self {
        self.defer_idle_timeout = config;
        self
    }

    /// Specify the [transport parameters] for the server connections.
    ///
    /// If you call this multiple times, only the last `parameters` will be used.
    ///
    /// Usually, you don't need to call this method, because the server will use a set of default parameters.
    ///
    /// [transport parameters](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit)
    pub fn with_parameters(mut self, parameters: ServerParameters) -> Self {
        self.parameters = parameters;
        self
    }

    /// Specify how hosts bind to the interface.
    ///
    /// If you call this multiple times, only the last `factory` will be used.
    ///
    /// The default interface is [`UdpSocketController`] that support GSO and GRO on linux,
    /// and the factory is [`UdpSocketController::bind`].
    pub fn with_iface_factory(self, factory: impl ProductQuicInterface + 'static) -> Self {
        Self {
            quic_iface_factory: Box::new(factory),
            ..self
        }
    }

    /// Specify qlog collector for server connections.
    ///
    /// If you call this multiple times, only the last `logger` will be used.
    ///
    /// We have pre-implemented two Qloggers:
    /// - [`DefaultSeqLogger`]: Generates a sqlog file for each connection,
    ///   which will be written to the directory specified when constructing [`DefaultSeqLogger`].
    ///   This Logger converts qlog to a lower version format that can be parsed by [qvis].
    ///
    /// - [`NullLogger`]: Ignores all qlogs, this is the default.
    ///
    /// [qvis]: https://qvis.quictools.info/
    /// [`DefaultSeqLogger`]: qevent::telemetry::handy::DefaultSeqLogger
    pub fn with_qlog(mut self, logger: Arc<dyn Log + Send + Sync>) -> Self {
        self.logger = Some(logger);
        self
    }
}

impl QuicListenersBuilder<TlsServerConfigBuilder<WantsVerifier>> {
    /// Choose how to verify client certificates.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn ClientCertVerifier>,
    ) -> QuicListenersBuilder<TlsServerConfig> {
        QuicListenersBuilder {
            global_guard: self.global_guard,
            supported_versions: self.supported_versions,
            quic_iface_factory: self.quic_iface_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_cert_verifier(client_cert_verifier)
                .with_cert_resolver(Arc::new(VirtualHosts(self.hosts.clone()))),
            hosts: self.hosts,
            ifaces: self.ifaces,
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger,
            token_provider: self.token_provider,
        }
    }

    /// Disable client authentication.
    pub fn without_client_cert_verifier(self) -> QuicListenersBuilder<TlsServerConfig> {
        QuicListenersBuilder {
            global_guard: self.global_guard,
            supported_versions: self.supported_versions,
            quic_iface_factory: self.quic_iface_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_cert_verifier(Arc::new(NoClientAuth))
                .with_cert_resolver(Arc::new(VirtualHosts(self.hosts.clone()))),
            hosts: self.hosts,
            ifaces: self.ifaces,
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger,
            token_provider: self.token_provider,
        }
    }
}

impl QuicListenersBuilder<TlsServerConfig> {
    /// Add a host with a certificate chain and a private key.
    ///
    /// Returns an error if the host has already been added, the private key is invalid,
    /// or one of the bind addresses specified in the [`HostBuilder`] fails to bind.
    ///
    /// Call this method multiple times to add multiple hosts,
    /// each with its own certificate chain and private key.  
    ///
    /// The server will use the certificate chain and private key
    /// that matches the SNI server name in the client's `ClientHello` message.
    /// If the client does not send an server name,
    /// or the server name don't match any host,
    /// the connection will be rejected by [`QuicListeners`].
    ///
    /// Host can be added without binding any interface.
    ///
    /// After the [`QuicListeners`] is started, you can call [`QuicListeners::add_interface`]
    /// to add more interfaces to the host, can  [`QuicListeners::del_interface`] to remove an
    /// interface from the host.
    pub fn add_host(
        self,
        name: impl Into<String>,
        host: impl Into<HostBuilder>,
    ) -> io::Result<Self> {
        let host_name = name.into();
        let new_host: HostBuilder = host.into();

        let host_entry = match self.hosts.entry(host_name.clone()) {
            dashmap::Entry::Vacant(entry) => entry,
            dashmap::Entry::Occupied(..) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("Host {host_name} already exists"),
                ));
            }
        };

        let signed_key = self
            .tls_config
            .crypto_provider()
            .key_provider
            .load_private_key(new_host.private_key)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Failed to load private key for host {host_name}: {e}"),
                )
            })?;

        let bind_addresses = new_host.bind_addresses.into_iter().try_fold(
            DashSet::new(),
            |bind_addresses, bind_address| {
                let iface_address = {
                    if let Some(listened_interface) = self.ifaces.get(&bind_address) {
                        let inserted = listened_interface.hosts.insert(host_name.clone());
                        assert!(!inserted);
                        listened_interface.iface.abstract_addr()
                    } else {
                        let iface = self.quic_iface_factory.bind(bind_address.clone())?;
                        let iface_addr = iface.abstract_addr();
                        crate::proto().add_interface(iface.clone());
                        let previous = self.ifaces.insert(
                            iface_addr.clone(),
                            BoundInterface {
                                iface,
                                hosts: [host_name.clone()].into_iter().collect(),
                            },
                        );
                        assert!(previous.is_none());
                        iface_addr
                    }
                };
                bind_addresses.insert(iface_address);
                io::Result::Ok(bind_addresses)
            },
        )?;

        host_entry.insert(Host {
            bind_addresses,
            cert_chain: new_host.cert_chain,
            private_key: signed_key,
            ocsp: new_host.ocsp,
        });

        Ok(self)
    }

    /// Specify the [alpn-protocol-ids] that the server supports.
    ///
    /// If you call this multiple times, all the `alpn_protocol` will be used.
    ///
    /// If you never call this method, we will not do ALPN with the client.
    ///
    /// [alpn-protocol-ids](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids)
    pub fn with_alpns(mut self, alpn: impl IntoIterator<Item = impl Into<Vec<u8>>>) -> Self {
        self.tls_config
            .alpn_protocols
            .extend(alpn.into_iter().map(Into::into));
        self
    }

    /// Start listening for incoming connections.
    ///
    /// Returns an error if no hosts have been added before.
    ///
    /// The `backlog` parameter has the same meaning as the backlog parameter of the UNIX listen function,
    /// which is the maximum number of pending connections that can be queued.
    /// If the queue is full, new initial packets may be dropped.
    pub fn listen(mut self, backlog: usize) -> io::Result<Arc<QuicListeners>> {
        if self.hosts.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "At least one host must be added",
            ));
        }

        let quic_listeners = Arc::new(QuicListeners {
            incomings: Arc::new(Channel::new(1)),
            _supported_versions: self.supported_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            hosts: self.hosts,
            ifaces: self.ifaces,
            tls_config: Arc::new(self.tls_config),
            stream_strategy_factory: self.stream_strategy_factory,
            backlog: Arc::new(Semaphore::new(backlog)),
            logger: self.logger.unwrap_or_else(|| Arc::new(NullLogger)),
            token_provider: self.token_provider,
        });

        *self.global_guard = Arc::downgrade(&quic_listeners);
        Ok(quic_listeners)
    }
}
