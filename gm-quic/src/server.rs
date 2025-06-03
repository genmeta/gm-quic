use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    sync::{Arc, RwLock, RwLockWriteGuard, Weak},
};

use dashmap::{DashMap, DashSet};
use handy::UdpSocketController;
use qconnection::builder::*;
use qevent::{
    quic::connectivity::ServerListening,
    telemetry::{Log, handy::NoopLogger},
};
use qinterface::util::Channel;
use rustls::{
    ConfigBuilder, ServerConfig as TlsServerConfig, WantsVerifier,
    server::{NoClientAuth, ResolvesServerCert, danger::ClientCertVerifier},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::*;

type TlsServerConfigBuilder<T> = ConfigBuilder<TlsServerConfig, T>;

#[derive(Debug, Default)]
pub struct VirtualHosts(Arc<DashMap<String, Server>>);

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

struct Server {
    bind_addresses: DashSet<BindAddr>,
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: Arc<dyn rustls::sign::SigningKey>,
    ocsp: Option<Vec<u8>>,
}

impl Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
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

/// An interface that has been bound to servers in the [`QuicListeners`].
struct BoundInterface {
    iface: Arc<dyn QuicInterface>,
    servers: DashSet<String>,
}

impl Debug for BoundInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenedInterface")
            .field("interface", &self.iface.bind_addr())
            .field("servers", &self.servers)
            .finish()
    }
}

impl Drop for BoundInterface {
    fn drop(&mut self) {
        crate::proto().del_interface_if(self.iface.bind_addr(), |iface, _| {
            Arc::ptr_eq(iface, &self.iface) && Arc::strong_count(iface) == 2
        });
    }
}

/// A QUIC listener that can serve multiple virtual servers, accepting incoming connections.
///
/// ## Creating Listeners
///
/// Use [`QuicListenersBuilder`] to configure the listener, then call [`QuicListenersBuilder::listen`]
/// to start accepting connections.
///
/// **Note**: Only one [`QuicListeners`] instance can run at a time globally.
/// To stop the listeners, call [`QuicListeners::shutdown`] or drop all references to the [`Arc<QuicListeners>`].
///
/// ## Managing Servers
///
/// Add multiple virtual servers by calling [`QuicListeners::add_server`] multiple times.
/// Each server is identified by its server name (SNI) and handles connections independently.
///
/// - Servers can share the same network interfaces
/// - Servers can be added without initially binding to any interface
/// - Use [`QuicListeners::add_interface`] to bind a server to additional interfaces
/// - Use [`QuicListeners::del_interface`] to remove a server from an interface
///
/// ## Connection Handling
///
/// Call [`QuicListeners::accept`] to receive incoming connections. The listener automatically:
/// - Routes connections to the appropriate server based on SNI (Server Name Indication)
/// - Rejects connections if the target server isn't listening on the receiving interface
/// - Returns connections that may still be completing their QUIC handshake
pub struct QuicListeners {
    quic_iface_factory: Box<dyn ProductQuicInterface>,
    ifaces: Arc<DashMap<BindAddr, BoundInterface>>,
    servers: Arc<DashMap<String, Server>>,
    backlog: Arc<Semaphore>,
    #[allow(clippy::type_complexity)]
    incomings: Arc<
        Channel<(
            (Arc<Connection>, String, Pathway, Link),
            OwnedSemaphorePermit,
        )>,
    >,

    token_provider: Arc<dyn TokenProvider>,
    parameters: ServerParameters,
    silent_rejection: bool,
    client_authers: Vec<Arc<dyn AuthClient>>,
    tls_config: Arc<TlsServerConfig>,
    stream_strategy_factory: Box<dyn ProductStreamsConcurrencyController>,
    defer_idle_timeout: HeartbeatConfig,
    logger: Arc<dyn Log + Send + Sync>,
    _supported_versions: Vec<u32>,
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
            quic_iface_factory: Box::new(UdpSocketController::bind),
            servers: Arc::default(),
            token_provider: None,
            parameters: ServerParameters::default(),
            silent_rejection: false,
            client_authers: vec![],
            tls_config,
            stream_strategy_factory: Box::new(ConsistentConcurrency::new),
            defer_idle_timeout: HeartbeatConfig::default(),
            logger: None,
            _supported_versions: vec![],
        })
    }

    /// Let the server bind to an interface.
    ///
    /// The server must have been added using [`add_server`], otherwise this method will return an error.
    ///
    /// If the added Interface has the same abstract address as an existing Interface but they are different instances,
    /// the old Interface will be replaced, and packets will no longer be accepted on the old Interface.
    ///
    /// [`add_server`]: QuicListeners::add_server
    pub fn add_interface(
        &self,
        server_name: impl Into<String>,
        iface: Arc<dyn QuicInterface>,
    ) -> io::Result<()> {
        let server_name = server_name.into();
        let new_addr = iface.read_addr()?;
        let Some(server_entry) = self.servers.get(&server_name) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Server {server_name} does not exist."),
            ));
        };
        // update or insert the interface
        let listened_interface = match self.ifaces.entry(iface.bind_addr()) {
            dashmap::Entry::Occupied(mut exist_iface) => {
                // if the interface on the same address is already exist, update if the interface is different
                if !Arc::ptr_eq(&iface, &exist_iface.get().iface) {
                    crate::proto().add_interface(iface.clone());
                    exist_iface.insert(BoundInterface {
                        iface: iface.clone(),
                        servers: exist_iface.get().servers.clone(),
                    });
                }
                exist_iface.into_ref()
            }
            dashmap::Entry::Vacant(vacant_entry) => {
                crate::proto().add_interface(iface.clone());
                vacant_entry.insert(BoundInterface {
                    iface: iface.clone(),
                    servers: DashSet::default(),
                })
            }
        };

        server_entry
            .bind_addresses
            .insert(listened_interface.iface.bind_addr());
        if listened_interface.servers.insert(server_name) {
            qevent::event!(ServerListening { address: new_addr });
        }

        Ok(())
    }

    /// Make a specific Server or all Servers stop listening on an interface.
    ///
    /// If `server_name` is not [`None`], only remove the interface for that server, which requires the Server to exist.
    /// If `server_name` is [`None`], make all Servers stop listening on that interface.
    ///
    /// If an Interface is no longer being listened to by any Server, the Interface will be released.
    /// However, a Server can listen on no interfaces.
    ///
    /// Removing an interface that has already been removed will return `Ok(())`.
    pub fn del_interface(
        &self,
        server_name: Option<impl Into<String>>,
        bind: BindAddr,
    ) -> io::Result<()> {
        let dashmap::Entry::Occupied(bind_interface) = self.ifaces.entry(bind.clone()) else {
            return Ok(());
        };
        match server_name {
            Some(server_name) => {
                let server_name = server_name.into();
                let Some(server_entry) = self.servers.get_mut(&server_name) else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Server {server_name} does not exist."),
                    ));
                };
                if server_entry.bind_addresses.remove(&bind).is_none() {
                    return Ok(()); // already removed
                }
                if server_entry.bind_addresses.is_empty() {
                    bind_interface.remove();
                }
            }
            None => {
                let bind_interface = bind_interface.remove();
                for server_name in bind_interface.servers.iter() {
                    let server = self
                        .servers
                        .get_mut(&*server_name)
                        .expect("Server must exist");
                    server.bind_addresses.remove(&bind);
                }
            }
        }
        Ok(())
    }

    /// Add a server with a certificate chain and a private key.
    ///
    /// Returns an error if the server has already been added, the private key is invalid,
    /// or one of the bind addresses fails to bind.
    ///
    /// Call this method multiple times to add multiple servers,
    /// each with its own certificate chain and private key.  
    ///
    /// The server will use the certificate chain and private key
    /// that matches the SNI server name in the client's `ClientHello` message.
    /// If the client does not send a server name,
    /// or the server name doesn't match any server,
    /// the connection will be rejected by [`QuicListeners`].
    ///
    /// A server can be added without binding any interface.
    ///
    /// After adding a server, you can call [`QuicListeners::add_interface`]
    /// to add more interfaces to the server, or [`QuicListeners::del_interface`] to remove an
    /// interface from the server.
    pub fn add_server(
        &self,
        server_name: impl Into<String>,
        cert_chain: impl ToCertificate,
        private_key: impl ToPrivateKey,
        bind_addresses: impl IntoIterator<Item = impl Into<BindAddr>>,
        ocsp: impl Into<Option<Vec<u8>>>,
    ) -> io::Result<()> {
        let server_name = server_name.into();

        let server_entry = match self.servers.entry(server_name.clone()) {
            dashmap::Entry::Vacant(entry) => entry,
            dashmap::Entry::Occupied(..) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("Server {server_name} already exists"),
                ));
            }
        };

        let cert_chain = cert_chain.to_certificate();
        let signed_key = self
            .tls_config
            .crypto_provider()
            .key_provider
            .load_private_key(private_key.to_private_key())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Failed to load private key for server {server_name}: {e}"),
                )
            })?;
        let ocsp = ocsp.into();

        let bind_addresses = bind_addresses.into_iter().map(Into::into).try_fold(
            DashSet::new(),
            |bind_addresses, bind_addr| {
                let bind_address = {
                    if let Some(listened_interface) = self.ifaces.get(&bind_addr) {
                        let inserted = listened_interface.servers.insert(server_name.clone());
                        assert!(!inserted);
                        listened_interface.iface.bind_addr()
                    } else {
                        let iface = self.quic_iface_factory.bind(bind_addr.clone())?;
                        let bind_addr = iface.bind_addr();
                        crate::proto().add_interface(iface.clone());
                        let previous = self.ifaces.insert(
                            bind_addr.clone(),
                            BoundInterface {
                                iface,
                                servers: [server_name.clone()].into_iter().collect(),
                            },
                        );
                        assert!(previous.is_none());
                        bind_addr
                    }
                };
                bind_addresses.insert(bind_address);
                io::Result::Ok(bind_addresses)
            },
        )?;

        server_entry.insert(Server {
            bind_addresses,
            cert_chain,
            private_key: signed_key,
            ocsp,
        });

        Ok(())
    }

    /// Gets all servers of the [`QuicListeners`] and their bound abstract addresses,
    /// as well as the actual addresses corresponding to the abstract addresses.
    ///
    /// If the Interface corresponding to an abstract address doesn't exist or is damaged,
    /// the corresponding actual address will be None.
    pub fn servers(&self) -> HashMap<String, HashMap<BindAddr, Option<RealAddr>>> {
        self.servers
            .iter()
            .map(|entry| {
                let addresses = entry
                    .value()
                    .bind_addresses
                    .iter()
                    .map(|addr| {
                        let iface = self.ifaces.get(&addr).expect("Interface must exist");
                        let local_addr = iface.iface.read_addr().ok();
                        (addr.key().clone(), local_addr)
                    })
                    .collect();
                let server_name = entry.key().to_owned();
                (server_name, addresses)
            })
            .collect()
    }

    /// Accept an incoming QUIC connection from the queue.
    ///
    /// Returns the connection, connected server name, and network path information.
    /// Connections are automatically routed based on SNI (Server Name Indication).
    ///
    /// The connection queue size is limited by the `backlog` parameter in [`QuicListenersBuilder::listen`].
    /// When the queue is full, new incoming packets may be dropped at the network level.
    pub async fn accept(&self) -> io::Result<(Arc<Connection>, String, Pathway, Link)> {
        self.incomings
            .recv()
            .await
            .ok_or_else(|| io::Error::other("Listeners shutdown"))
            .map(|(i, ..)| i)
    }

    /// Close the QuicListeners, stops accepting new connections.
    ///
    /// Unaccepted connections will be closed
    pub fn shutdown(&self) {
        if self.incomings.close().is_none() {
            // already closed
            return;
        }

        self.incomings.close();
    }
}

impl Drop for QuicListeners {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct ServerAuther {
    iface: BindAddr,
    servers: Arc<DashMap<String, Server>>,
}

impl AuthClient for ServerAuther {
    fn verify_client_params(&self, host: &str, _: Option<&str>) -> bool {
        self.servers
            .get(host)
            .is_some_and(|server| server.bind_addresses.contains(&self.iface))
    }

    fn verify_client_certs(&self, _: &str, _: Option<&str>, _: &PeerCert) -> bool {
        true
    }
}

// internal methods
impl QuicListeners {
    fn global() -> &'static RwLock<Weak<QuicListeners>> {
        static LISTENERS: OnceLock<RwLock<Weak<QuicListeners>>> = OnceLock::new();
        LISTENERS.get_or_init(Default::default)
    }

    pub(crate) async fn try_accept_connection(
        bind_addr: BindAddr,
        packet: Packet,
        pathway: Pathway,
        link: Link,
    ) {
        let Some(listeners) = Self::global().read().unwrap().upgrade() else {
            return;
        };

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

        let server_auther: Arc<dyn AuthClient> = Arc::new(ServerAuther {
            iface: bind_addr.clone(),
            servers: listeners.servers.clone(),
        });

        let client_authers = [server_auther]
            .into_iter()
            .chain(listeners.client_authers.iter().cloned());

        let (event_broker, mut events) = mpsc::unbounded_channel();

        let connection = Arc::new(
            Connection::with_token_provider(listeners.token_provider.clone())
                .with_parameters(listeners.parameters.clone())
                .with_silent_rejection(listeners.silent_rejection)
                .with_client_authers(client_authers)
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
                .deliver(bind_addr.clone(), packet, pathway, link)
                .await;

            tokio::spawn({
                let connection = connection.clone();
                async move {
                    while let Some(event) = events.recv().await {
                        match event {
                            Event::Handshaked => {}
                            Event::ProbedNewPath(..) => {}
                            Event::PathInactivated(bind_addr, ..) => {
                                crate::proto().try_free_interface(bind_addr);
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
                    let incoming = (connection.clone(), server_name, pathway, link);
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
        bind_addr: BindAddr,
        broken_iface: Weak<dyn QuicInterface>,
        error: io::Error,
    ) {
        let Some(listeners) = Self::global().read().unwrap().upgrade() else {
            return;
        };

        if let Some(listened_interface) = listeners.ifaces.get(&bind_addr) {
            if Weak::ptr_eq(&Arc::downgrade(&listened_interface.iface), &broken_iface) {
                for server_name in listened_interface.servers.iter() {
                    let server_name = &*server_name;
                    tracing::error!(
                        "Interface {bind_addr} used by {server_name} was closed unexpectedly: {error:?}."
                    );
                }
            }
        };
    }
}

/// The builder for the quic listeners.
pub struct QuicListenersBuilder<T> {
    global_guard: RwLockWriteGuard<'static, Weak<QuicListeners>>,
    quic_iface_factory: Box<dyn ProductQuicInterface>,
    servers: Arc<DashMap<String, Server>>, // must be empty while building

    token_provider: Option<Arc<dyn TokenProvider>>,
    parameters: ServerParameters,
    silent_rejection: bool,
    client_authers: Vec<Arc<dyn AuthClient>>,
    tls_config: T,
    stream_strategy_factory: Box<dyn ProductStreamsConcurrencyController>,
    defer_idle_timeout: HeartbeatConfig,
    logger: Option<Arc<dyn Log + Send + Sync>>,
    _supported_versions: Vec<u32>,
}

impl<T> QuicListenersBuilder<T> {
    /// (WIP)Specify the supported quic versions.
    ///
    /// If you call this multiple times, only the last call will take effect.
    pub fn with_supported_versions(mut self, versions: impl IntoIterator<Item = u32>) -> Self {
        self._supported_versions.clear();
        self._supported_versions.extend(versions);
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
    /// - [`NoopLogger`]: Ignores all qlogs, this is the default.
    ///
    /// [qvis]: https://qvis.quictools.info/
    /// [`DefaultSeqLogger`]: qevent::telemetry::handy::DefaultSeqLogger
    pub fn with_qlog(mut self, logger: Arc<dyn Log + Send + Sync>) -> Self {
        self.logger = Some(logger);
        self
    }

    /// Enable silent rejection mode for enhanced security.
    ///
    /// When silent rejection is enabled, the server will silently drop connections
    /// that fail validation (e.g., invalid ClientHello, authentication failures)
    /// without sending any response packets.
    ///
    /// This security feature provides the following benefits:
    /// - Prevents attackers from gaining information about server presence
    /// - Reduces the attack surface by not revealing server configuration details
    /// - Protects against network reconnaissance and scanning attacks
    /// - Makes the server appear "offline" to unauthorized connection attempts
    ///
    /// **Security Note:** This feature should be used carefully as it may make
    /// debugging connection issues more difficult. Consider using it in production
    /// environments where security is prioritized over observability.
    ///
    /// **Tip:** For enhanced security, combine this with [`with_client_authers`] to implement
    /// custom authentication logic while maintaining stealth behavior for failed connections.
    ///
    /// Default: disabled
    ///
    /// [`with_client_authers`]: QuicListenersBuilder::with_client_authers
    pub fn enable_silent_rejection(mut self) -> Self {
        self.silent_rejection = true;
        self
    }

    /// Specify custom client authentication handlers for the server.
    ///
    /// Client authers are used to perform additional validation beyond standard TLS
    /// certificate verification. They can verify server names, client parameters,
    /// and client certificates according to custom business logic.
    ///
    /// Each [`AuthClient`] implementation provides three verification methods:
    /// - `verify_server_name()`: Validates the requested server name (SNI)
    /// - `verify_client_params()`: Validates client QUIC transport parameters
    /// - `verify_client_certs()`: Validates client certificate chains
    ///
    /// All provided authers must approve the connection for it to be accepted.
    /// If any auther rejects the connection, it will be dropped.
    ///
    /// If you call this multiple times, only the last `client_authers` will be used.
    ///
    /// **Security Enhancement:** When combined with [`enable_silent_rejection`],
    /// failed authentication attempts will be silently dropped without any response,
    /// providing enhanced security against reconnaissance attacks.
    ///
    /// **TLS Protocol Note:** Due to TLS protocol certificate verification failures
    /// will still send error responses to clients, as the server has already sent
    /// its `ServerHello` message at that point. Silent rejection only applies to
    /// earlier validation failures.
    ///
    /// **Built-in Validation:** The server automatically verifies that the interface
    /// receiving the client connection is configured to listen for the requested
    /// server name (SNI). This built-in validation ensures proper routing of
    /// connections to their intended hosts.
    ///
    /// Default: empty (only built-in host and interface validation)
    ///
    /// [`AuthClient`]: qconnection::tls::AuthClient
    /// [`enable_silent_rejection`]: QuicListenersBuilder::enable_silent_rejection
    pub fn with_client_authers(
        mut self,
        client_authers: impl IntoIterator<Item = Arc<dyn AuthClient>>,
    ) -> Self {
        self.client_authers = client_authers.into_iter().collect();
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
            quic_iface_factory: self.quic_iface_factory,
            servers: self.servers.clone(),
            token_provider: self.token_provider,
            parameters: self.parameters,
            silent_rejection: self.silent_rejection,
            client_authers: self.client_authers,
            tls_config: self
                .tls_config
                .with_client_cert_verifier(client_cert_verifier)
                .with_cert_resolver(Arc::new(VirtualHosts(self.servers))),
            stream_strategy_factory: self.stream_strategy_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            logger: self.logger,
            _supported_versions: self._supported_versions,
        }
    }

    /// Disable client authentication.
    pub fn without_client_cert_verifier(self) -> QuicListenersBuilder<TlsServerConfig> {
        QuicListenersBuilder {
            global_guard: self.global_guard,
            quic_iface_factory: self.quic_iface_factory,
            servers: self.servers.clone(),
            token_provider: self.token_provider,
            parameters: self.parameters,
            silent_rejection: self.silent_rejection,
            client_authers: self.client_authers,
            tls_config: self
                .tls_config
                .with_client_cert_verifier(Arc::new(NoClientAuth))
                .with_cert_resolver(Arc::new(VirtualHosts(self.servers))),
            stream_strategy_factory: self.stream_strategy_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            logger: self.logger,
            _supported_versions: self._supported_versions,
        }
    }
}

impl QuicListenersBuilder<TlsServerConfig> {
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
    /// The `backlog` parameter has the same meaning as the backlog parameter of the UNIX listen function,
    /// which is the maximum number of pending connections that can be queued.
    /// If the queue is full, new initial packets may be dropped.
    ///
    /// Panic if `backlog` is 0.
    pub fn listen(mut self, backlog: usize) -> Arc<QuicListeners> {
        assert!(backlog > 0, "backlog must be greater than 0");
        debug_assert!(self.servers.is_empty());

        let quic_listeners = Arc::new(QuicListeners {
            quic_iface_factory: self.quic_iface_factory,
            ifaces: Arc::default(),
            servers: self.servers,
            backlog: Arc::new(Semaphore::new(backlog)),
            incomings: Arc::new(Channel::new(8)), // any number greater than 0
            token_provider: self
                .token_provider
                .unwrap_or_else(|| Arc::new(NoopTokenRegistry)),
            parameters: self.parameters,
            silent_rejection: self.silent_rejection,
            client_authers: self.client_authers,
            tls_config: Arc::new(self.tls_config),
            stream_strategy_factory: self.stream_strategy_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            logger: self.logger.unwrap_or_else(|| Arc::new(NoopLogger)),
            _supported_versions: self._supported_versions,
        });

        *self.global_guard = Arc::downgrade(&quic_listeners);
        quic_listeners
    }
}
