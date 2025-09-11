use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    io,
    ops::Deref,
    sync::{Arc, RwLock, Weak},
    time::Duration,
};

use dashmap::DashMap;
use qbase::util::BoundQueue;
use qconnection::{builder::*, prelude::handy::ConsistentConcurrency};
use qevent::telemetry::{Log, handy::NoopLogger};
use qinterface::{
    factory::ProductQuicIO,
    iface::{BindInterface, QuicInterfaces},
    route::{Router, Way},
};
use rustls::{
    ConfigBuilder, ServerConfig as TlsServerConfig, WantsVerifier,
    pki_types::CertificateDer,
    server::{NoClientAuth, ResolvesServerCert, danger::ClientCertVerifier},
    sign::SigningKey,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::Instrument;

use crate::*;

/// Errors that can occur during server management operations.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The server with the specified name already exists.
    #[error("Server '{name}' already exists")]
    ServerAlreadyExists { name: String },

    /// The server with the specified name was not found.
    #[error("Server '{name}' not found")]
    ServerNotFound { name: String },

    /// Failed to load the private key for the server.
    #[error("Failed to load private key for server '{server_name}': {source}")]
    InvalidPrivateKey {
        server_name: String,
        #[source]
        source: rustls::Error,
    },
}

impl From<ServerError> for io::Error {
    fn from(err: ServerError) -> Self {
        match err {
            ServerError::ServerAlreadyExists { .. } => {
                io::Error::new(io::ErrorKind::AlreadyExists, err)
            }
            ServerError::ServerNotFound { .. } => io::Error::new(io::ErrorKind::NotFound, err),
            ServerError::InvalidPrivateKey { .. } => {
                io::Error::new(io::ErrorKind::InvalidInput, err)
            }
        }
    }
}

/// Errors that can occur during QuicListeners builder creation.
#[derive(Debug, thiserror::Error)]
pub enum BuildServerError {
    /// A QuicListeners instance is already running globally.
    #[error("A QuicListeners is already running, please shutdown it first")]
    AlreadyRunning,

    /// Failed to create TLS configuration with the crypto provider.
    #[error("Failed to create TLS configuration with crypto provider: {source}")]
    CryptoProviderConfigError {
        #[source]
        source: rustls::Error,
    },
}

impl From<BuildServerError> for io::Error {
    fn from(err: BuildServerError) -> Self {
        match err {
            BuildServerError::AlreadyRunning => io::Error::new(io::ErrorKind::AlreadyExists, err),
            BuildServerError::CryptoProviderConfigError { .. } => {
                io::Error::new(io::ErrorKind::InvalidInput, err)
            }
        }
    }
}

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

#[derive(Debug)]
pub struct Server {
    bind_ifaces: DashMap<BindUri, BindInterface>,
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: Arc<dyn SigningKey>,
    ocsp: Option<Vec<u8>>,
}

impl Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bind_ifaces = self
            .bind_ifaces
            .iter()
            .map(
                |entry| match entry.value().borrow().and_then(|iface| iface.real_addr()) {
                    Ok(real_addr) => format!("{}: {}", entry.key(), real_addr),
                    Err(e) => format!("{}: <unknown address: {e}>", entry.key()),
                },
            )
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "[{bind_ifaces}]")
    }
}

impl Server {
    pub fn bind_interfaces(&self) -> HashMap<BindUri, BindInterface> {
        self.bind_ifaces
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    pub fn add_interface(&self, interface: BindInterface) {
        self.bind_ifaces
            .entry(interface.bind_uri())
            .or_insert(interface);
    }

    pub fn get_interface(&self, bind_uri: &BindUri) -> Option<BindInterface> {
        self.bind_ifaces
            .get(bind_uri)
            .map(|iface| iface.value().clone())
    }

    pub fn unbind_interface(&self, bind_uri: &BindUri) -> Option<BindInterface> {
        self.bind_ifaces.remove(bind_uri).map(|entry| entry.1)
    }

    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }

    pub fn private_key(&self) -> &Arc<dyn SigningKey> {
        &self.private_key
    }

    pub fn ocsp(&self) -> Option<&[u8]> {
        self.ocsp.as_deref()
    }
}

type Incomings = BoundQueue<(
    (Arc<Connection>, String, Pathway, Link),
    OwnedSemaphorePermit,
)>;

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
///
/// ## Connection Handling
///
/// Call [`QuicListeners::accept`] to receive incoming connections. The listener automatically:
/// - Routes connections to the appropriate server based on SNI (Server Name Indication)
/// - Rejects connections if the target server isn't listening on the receiving interface
/// - Returns connections that may still be completing their QUIC handshake
pub struct QuicListeners {
    quic_iface_factory: Arc<dyn ProductQuicIO>,
    ifaces: Arc<QuicInterfaces>,
    servers: Arc<DashMap<String, Server>>,
    backlog: Arc<Semaphore>,
    #[allow(clippy::type_complexity)]
    incomings: Arc<Incomings>,

    token_provider: Arc<dyn TokenProvider>,
    parameters: ServerParameters,
    anti_port_scan: bool,
    client_auther: Arc<dyn AuthClient>,
    tls_config: TlsServerConfig,
    stream_strategy_factory: Box<dyn ProductStreamsConcurrencyController>,
    defer_idle_timeout: Duration,
    logger: Arc<dyn Log + Send + Sync>,
    _supported_versions: Vec<u32>,
}

impl QuicListeners {
    /// Start to build a [`QuicListeners`].
    pub fn builder()
    -> Result<QuicListenersBuilder<TlsServerConfigBuilder<WantsVerifier>>, BuildServerError> {
        Self::builder_with_tls(TlsServerConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS13,
        ]))
    }

    /// Start to build a QuicServer with the given tls crypto provider.
    pub fn builder_with_crypto_provider(
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<QuicListenersBuilder<TlsServerConfigBuilder<WantsVerifier>>, BuildServerError> {
        Self::builder_with_tls(
            TlsServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| BuildServerError::CryptoProviderConfigError { source: e })?,
        )
    }

    /// Start to build a [`QuicListeners`] with the given TLS configuration.
    ///
    /// This is useful when you want to customize the TLS configuration, or integrate qm-quic with other crates.
    pub fn builder_with_tls<T>(tls_config: T) -> Result<QuicListenersBuilder<T>, BuildServerError> {
        let mut global_incomings = QuicListeners::global()
            .write()
            .expect("QuicListeners global lock");
        if let Some(incomings) = global_incomings.upgrade() {
            if !incomings.is_closed() {
                return Err(BuildServerError::AlreadyRunning);
            }
        }

        let incomings = Arc::new(Incomings::new(8));
        *global_incomings = Arc::downgrade(&incomings);

        Ok(QuicListenersBuilder {
            incomings,
            quic_iface_factory: Arc::new(handy::DEFAULT_QUIC_IO_FACTORY),
            servers: Arc::default(),
            token_provider: None,
            parameters: handy::server_parameters(),
            anti_port_scan: false,
            client_auther: Arc::new(AcceptAllClientAuther),
            tls_config,
            stream_strategy_factory: Box::new(ConsistentConcurrency::new),
            defer_idle_timeout: Duration::ZERO,
            logger: None,
            _supported_versions: vec![],
        })
    }

    /// Add a virtual server with its certificate chain and private key.
    ///
    /// Creates a new virtual host identified by its server name (SNI). The server will use the
    /// certificate chain and private key that matches the SNI in the client's `ClientHello` message.
    /// If no matching server is found, the connection will be rejected.
    ///
    /// A server can be added without binding to any interface initially, but will not accept
    /// connections until interfaces are added via [`bind_interfaces`]. This allows flexible
    /// server configuration and hot-swapping of network bindings.
    ///
    /// # Related Methods
    ///
    /// - [`bind_interfaces`] - Add more interfaces to this server
    /// - [`unbind_interface`] - Remove specific interfaces
    /// - [`remove_server`] - Remove the entire server
    ///
    /// [`bind_interfaces`]: QuicListeners::bind_interfaces
    /// [`unbind_interface`]: QuicListeners::unbind_interface
    /// [`remove_server`]: QuicListeners::remove_server
    pub fn add_server(
        &self,
        server_name: impl Into<String>,
        cert_chain: impl ToCertificate,
        private_key: impl ToPrivateKey,
        bind_uris: impl IntoIterator<Item = impl Into<BindUri>>,
        ocsp: impl Into<Option<Vec<u8>>>,
    ) -> Result<(), ServerError> {
        let server_name = server_name.into();

        let server_entry = match self.servers.entry(server_name.clone()) {
            dashmap::Entry::Vacant(entry) => entry,
            dashmap::Entry::Occupied(..) => {
                return Err(ServerError::ServerAlreadyExists { name: server_name });
            }
        };

        let cert_chain = cert_chain.to_certificate();
        let signed_key = self
            .tls_config
            .crypto_provider()
            .key_provider
            .load_private_key(private_key.to_private_key())
            .map_err(|e| ServerError::InvalidPrivateKey {
                server_name: server_name.clone(),
                source: e,
            })?;
        let ocsp = ocsp.into();

        let bind_ifaces =
            bind_uris
                .into_iter()
                .map(Into::into)
                .fold(DashMap::new(), |bind_ifaces, bind_uri| {
                    bind_ifaces.entry(bind_uri.clone()).or_insert_with(|| {
                        self.ifaces
                            .bind(bind_uri.clone(), self.quic_iface_factory.clone())
                    });
                    bind_ifaces
                });

        server_entry.insert(Server {
            bind_ifaces,
            cert_chain,
            private_key: signed_key,
            ocsp,
        });

        Ok(())
    }

    /// Remove a virtual server and all its associated interfaces.
    ///
    /// Completely removes a server from the listeners, including all network interfaces
    /// it was bound to (if the interface is not used by other servers).
    /// This is the inverse operation of [`add_server`] and provides a clean
    /// way to decommission a virtual host.
    ///
    /// Returns `true` if the server existed and was removed, `false` if no server with the
    /// specified name was found. You must remove an existing server before adding a new
    /// one with the same name.
    ///
    /// # Related Methods
    ///
    /// - [`add_server`] - Create a server (counterpart operation)
    /// - [`unbind_interface`] - Remove specific interfaces only
    ///
    /// [`add_server`]: QuicListeners::add_server
    /// [`unbind_interface`]: QuicListeners::unbind_interface
    pub fn remove_server(&self, server_name: &str) -> bool {
        self.servers.remove(server_name).is_some()
    }

    /// Add additional network interfaces to an existing virtual server.
    ///
    /// Extends an existing server to listen on additional network interfaces, enabling
    /// horizontal scaling and multi-homed server configurations. Interfaces that are
    /// already bound to the server will be silently ignored, allowing for idempotent operations.
    ///
    /// The server must have been created with [`add_server`] first. Added interfaces can later
    /// be removed selectively with [`unbind_interface`], supporting hot-swapping and zero-downtime
    /// updates.
    ///
    /// # Related Methods
    ///
    /// - [`add_server`] - Create the server first
    /// - [`unbind_interface`] - Remove specific interfaces
    ///
    /// [`add_server`]: QuicListeners::add_server
    /// [`unbind_interface`]: QuicListeners::unbind_interface
    pub fn bind_interfaces(
        &self,
        server_name: impl Into<String>,
        bind_uris: impl IntoIterator<Item = impl Into<BindUri>>,
    ) -> Result<(), ServerError> {
        let server_name = server_name.into();
        let server_entry = match self.servers.entry(server_name.clone()) {
            dashmap::Entry::Occupied(server_entry) => server_entry,
            dashmap::Entry::Vacant(..) => {
                return Err(ServerError::ServerNotFound { name: server_name });
            }
        };

        for bind_uri in bind_uris.into_iter().map(Into::into) {
            if let dashmap::Entry::Vacant(iface_entry) =
                server_entry.get().bind_ifaces.entry(bind_uri.clone())
            {
                let factory = self.quic_iface_factory.clone();
                let interface = self.ifaces.bind(bind_uri.clone(), factory);
                iface_entry.insert(interface);
            }
        }

        Ok(())
    }

    /// Get the server by its name.
    pub fn get_server<'l>(&'l self, server_name: &str) -> Option<impl Deref<Target = Server> + 'l> {
        self.servers.get(server_name)
    }

    /// Remove a specific network interface from one or more servers.
    ///
    /// Provides fine-grained control over interface management, allowing selective removal
    /// of interfaces without affecting the server's core configuration or other interfaces.
    /// This is the counterpart to [`bind_interfaces`] for flexible network topology management.
    ///
    /// The `server_names` parameter controls the scope:
    /// - `Some(server_names)` - Remove the interface only from specified servers
    /// - `None` - Remove the interface from ALL servers currently using it
    ///
    /// Operations are graceful: non-existent servers or unbound interfaces are silently ignored,
    /// enabling safe cleanup and idempotent scripts.
    ///
    /// # Related Methods
    ///
    /// - [`bind_interfaces`] - Add interfaces (counterpart operation)
    /// - [`remove_server`] - Remove entire server instead
    ///
    /// [`bind_interfaces`]: QuicListeners::bind_interfaces
    /// [`remove_server`]: QuicListeners::remove_server
    pub fn unbind_interface<'s>(
        &self,
        server_names: Option<impl IntoIterator<Item = &'s str>>,
        bind_uri: BindUri,
    ) {
        match server_names {
            Some(server_names) => server_names
                .into_iter()
                .filter_map(|server_name| self.servers.get(server_name))
                .for_each(|server| {
                    server.bind_ifaces.remove(&bind_uri);
                }),
            None => self.servers.iter().for_each(|entry| {
                entry.value().bind_ifaces.remove(&bind_uri);
            }),
        }
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
        self.incomings.close();
        self.backlog.close();

        let global = Self::global().read().unwrap();
        if let Some(global) = global.upgrade() {
            if global.same_queue(&self.incomings) {
                Router::global().on_connectless_packets(|_, _| {});
            }
        }
    }
}

impl Drop for QuicListeners {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct ServerAuther {
    anti_port_scan: bool,
    iface: BindUri,
    servers: Arc<DashMap<String, Server>>,
}

impl AuthClient for ServerAuther {
    fn verify_client_name(&self, host: &str, _: Option<&str>) -> ClientNameVerifyResult {
        match self
            .servers
            .get(host)
            .is_some_and(|server| server.bind_ifaces.contains_key(&self.iface))
        {
            true => ClientNameVerifyResult::Accept,
            false if self.anti_port_scan => ClientNameVerifyResult::SilentRefuse("".to_owned()),
            false => ClientNameVerifyResult::Refuse("".to_owned()),
        }
    }

    fn verify_client_certs(&self, _: &str, _: Option<&str>, _: &[u8]) -> ClientCertsVerifyResult {
        ClientCertsVerifyResult::Accept
    }
}

// internal methods
impl QuicListeners {
    fn global() -> &'static RwLock<Weak<Incomings>> {
        static INCOMINGS: OnceLock<RwLock<Weak<Incomings>>> = OnceLock::new();
        INCOMINGS.get_or_init(Default::default)
    }

    #[tracing::instrument(
        target = "quic_server", level = "debug", skip_all, 
        fields(%bind_uri, %pathway, %link, odcid=tracing::field::Empty, server_name=tracing::field::Empty)
    )]
    pub(crate) fn try_accept_connection(&self, packet: Packet, (bind_uri, pathway, link): Way) {
        // Acquire a permit from the backlog semaphore to limit the number of concurrent connections.
        let Ok(premit) = self.backlog.clone().try_acquire_owned() else {
            tracing::debug!(target: "quic_server", "Backlog full, dropping incoming packet");
            return;
        };

        let origin_dcid = match &packet {
            Packet::Data(data_packet) => match &data_packet.header {
                DataHeader::Long(LongHeader::Initial(hdr)) => *hdr.dcid(),
                DataHeader::Long(LongHeader::ZeroRtt(hdr)) => *hdr.dcid(),
                _ => return,
            },
            _ => return,
        };
        tracing::Span::current().record("odcid", origin_dcid.to_string());

        if origin_dcid.is_empty() {
            tracing::debug!(target: "quic_server", "Received an initial/0rtt packet with empty destination CID, ignoring it");
            return;
        }

        let server_auther = ServerAuther {
            anti_port_scan: self.anti_port_scan,
            iface: bind_uri.clone(),
            servers: self.servers.clone(),
        };

        let connection = Arc::new(
            Connection::new_server(self.token_provider.clone())
                .with_parameters(self.parameters.clone())
                .with_client_auther(Box::new((server_auther, self.client_auther.clone())))
                .with_tls_config(self.tls_config.clone())
                .with_streams_concurrency_strategy(self.stream_strategy_factory.as_ref())
                .with_zero_rtt(self.tls_config.max_early_data_size == 0xffffffff)
                .with_defer_idle_timeout(self.defer_idle_timeout)
                .with_cids(origin_dcid)
                .with_qlog(self.logger.clone())
                .run(),
        );

        let incomings = self.incomings.clone();

        let try_accept_connection = async move {
            Router::global()
                .deliver(packet, (bind_uri.clone(), pathway, link))
                .await;

            match connection.server_name().await {
                Ok(server_name) => {
                    tracing::Span::current().record("server_name", &server_name);
                    let incoming = (connection.clone(), server_name, pathway, link);
                    if incomings.send((incoming, premit)).await.is_err() {
                        connection.close("", 1);
                    }
                }
                Err(error) => {
                    tracing::error!(
                        target: "quic_server",
                        "Failed to accept connection from: {error:?}",
                    );
                }
            }
        };
        tokio::spawn(try_accept_connection.in_current_span());
    }
}

/// The builder for the quic listeners.
pub struct QuicListenersBuilder<T> {
    quic_iface_factory: Arc<dyn ProductQuicIO>,
    servers: Arc<DashMap<String, Server>>, // must be empty while building
    incomings: Arc<Incomings>,             // identify the building QuicListeners

    token_provider: Option<Arc<dyn TokenProvider>>,
    parameters: ServerParameters,
    anti_port_scan: bool,
    client_auther: Arc<dyn AuthClient>,
    tls_config: T,
    stream_strategy_factory: Box<dyn ProductStreamsConcurrencyController>,
    defer_idle_timeout: Duration,
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
    pub fn defer_idle_timeout(mut self, duration: Duration) -> Self {
        self.defer_idle_timeout = duration;
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
    /// The default quic interface is provided by [`handy::DEFAULT_QUIC_IO_FACTORY`].
    /// For Unix and Windows targets, this is a high performance UDP library supporting GSO and GRO
    /// provided by `qudp` crate. For other platforms, please specify you own factory.
    pub fn with_iface_factory(self, factory: impl ProductQuicIO + 'static) -> Self {
        Self {
            quic_iface_factory: Arc::new(factory),
            ..self
        }
    }

    /// Specify qlog collector for server connections.
    ///
    /// If you call this multiple times, only the last `logger` will be used.
    ///
    /// Pre-implemented loggers:
    /// - [`LegacySeqLogger`]: Generates qlog files compatible with [qvis] visualization.
    ///   - `LegacySeqLogger::new(PathBuf::from("/dir"))`: Write to files `{connection_id}_{role}.sqlog` in `dir`
    ///   - `LegacySeqLogger::new(tokio::io::stdout())`: Stream to stdout
    ///   - `LegacySeqLogger::new(tokio::io::stderr())`: Stream to stderr
    ///
    ///   Output format: JSON-SEQ ([RFC7464]), one JSON event per line.
    ///
    /// - [`NoopLogger`]: Ignores all qlog events (default, recommended for production).
    ///
    /// [qvis]: https://qvis.quictools.info/
    /// [RFC7464]: https://www.rfc-editor.org/rfc/rfc7464
    /// [`LegacySeqLogger`]: qevent::telemetry::handy::LegacySeqLogger
    pub fn with_qlog(mut self, logger: Arc<dyn Log + Send + Sync>) -> Self {
        self.logger = Some(logger);
        self
    }

    /// Enable anti-port scanning protection.
    ///
    /// When anti-port scanning protection is enabled, the server will silently drop connections
    /// that fail validation (e.g., invalid ClientHello, authentication failures)
    /// without sending any response packets.
    ///
    /// This security feature provides the following benefits:
    /// - Prevents attackers from detecting server presence through port scanning
    /// - Reduces the attack surface by not revealing server configuration details
    /// - Protects against network reconnaissance and probing attacks
    /// - Makes the server appear "offline" to unauthorized connection attempts
    ///
    /// **Security Note:** This feature should be used carefully as it may make
    /// debugging connection issues more difficult. Consider using it in production
    /// environments where security is prioritized over observability.
    ///
    /// **Tip:** For enhanced security, combine this with [`with_client_auther`] to implement
    /// custom authentication logic while maintaining stealth behavior for failed connections.
    ///
    /// Default: disabled
    ///
    /// [`with_client_auther`]: QuicListenersBuilder::with_client_auther
    pub fn enable_anti_port_scan(mut self) -> Self {
        self.anti_port_scan = true;
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
    /// If you call this multiple times, only the last `client_auther` will be used.
    ///
    /// **Security Enhancement:** When combined with [`enable_anti_port_scan`],
    /// failed authentication attempts will be silently dropped without any response,
    /// providing enhanced security against reconnaissance attacks.
    ///
    /// **TLS Protocol Note:** Certificate verification failures during the TLS handshake
    /// will still send error responses to clients, as the server has already sent
    /// its `ServerHello` message at that point. The stealth behavior only applies to
    /// earlier validation failures that occur before the TLS handshake begins.
    ///
    /// **Built-in Validation:** The server automatically verifies that the interface
    /// receiving the client connection is configured to listen for the requested
    /// server name (SNI). This built-in validation ensures proper routing of
    /// connections to their intended hosts.
    ///
    /// Default: empty (only built-in host and interface validation)
    ///
    /// [`AuthClient`]: qconnection::tls::AuthClient
    /// [`enable_anti_port_scan`]: QuicListenersBuilder::enable_anti_port_scan
    pub fn with_client_auther(mut self, client_auther: impl AuthClient + 'static) -> Self {
        self.client_auther = Arc::new(client_auther);
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
            quic_iface_factory: self.quic_iface_factory,
            servers: self.servers.clone(),
            incomings: self.incomings,
            token_provider: self.token_provider,
            parameters: self.parameters,
            anti_port_scan: self.anti_port_scan,
            client_auther: self.client_auther,
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
            quic_iface_factory: self.quic_iface_factory,
            servers: self.servers.clone(),
            incomings: self.incomings,
            token_provider: self.token_provider,
            parameters: self.parameters,
            anti_port_scan: self.anti_port_scan,
            client_auther: self.client_auther,
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

    pub fn enable_0rtt(mut self) -> Self {
        // The TLS early_data extension in the NewSessionTicket message is defined to convey (in the
        // max_early_data_size parameter) the amount of TLS 0-RTT data the server is willing to accept. QUIC does not
        // use TLS early data. QUIC uses 0-RTT packets to carry early data. Accordingly, the max_early_data_size
        // parameter is repurposed to hold a sentinel value 0xffffffff to indicate that the server is willing to accept QUIC
        // 0-RTT data. To indicate that the server does not accept 0-RTT data, the early_data extension is omitted from
        // the NewSessionTicket. The amount of data that the client can send in QUIC 0-RTT is controlled by the
        // initial_max_data transport parameter supplied by the server.
        self.tls_config.max_early_data_size = 0xffffffff;
        self
    }

    /// Start listening for incoming connections.
    ///
    /// The `backlog` parameter has the same meaning as the backlog parameter of the UNIX listen function,
    /// which is the maximum number of pending connections that can be queued.
    /// If the queue is full, new initial packets may be dropped.
    ///
    /// Panic if `backlog` is 0.
    pub fn listen(self, backlog: usize) -> Arc<QuicListeners> {
        assert!(backlog > 0, "backlog must be greater than 0");
        debug_assert!(self.servers.is_empty());

        let quic_listeners = Arc::new(QuicListeners {
            quic_iface_factory: self.quic_iface_factory,
            ifaces: QuicInterfaces::global().clone(),
            servers: self.servers,
            backlog: Arc::new(Semaphore::new(backlog)),
            incomings: self.incomings, // size: any number greater than 0
            token_provider: self
                .token_provider
                .unwrap_or_else(|| Arc::new(handy::NoopTokenRegistry)),
            parameters: self.parameters,
            anti_port_scan: self.anti_port_scan,
            client_auther: self.client_auther,
            tls_config: self.tls_config,
            stream_strategy_factory: self.stream_strategy_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            logger: self.logger.unwrap_or_else(|| Arc::new(NoopLogger)),
            _supported_versions: self._supported_versions,
        });

        Router::global().on_connectless_packets({
            let quic_listeners = quic_listeners.clone();
            move |packet, way| quic_listeners.try_accept_connection(packet, way)
        });

        quic_listeners
    }
}
