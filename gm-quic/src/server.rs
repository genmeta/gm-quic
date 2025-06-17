use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    future::Future,
    io,
    sync::{Arc, RwLock, Weak},
};

use dashmap::{DashMap, DashSet};
use handy::UdpSocketController;
use qconnection::{builder::*, prelude::handy::ConsistentConcurrency};
use qevent::telemetry::{Log, handy::NoopLogger};
use qinterface::{
    ifaces::{QuicInterfaces, borrowed::BorrowedInterface},
    route::Router,
    util::Channel,
};
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
    iface: Arc<BorrowedInterface>,
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

type Incomings = Channel<(
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
    quic_iface_factory: Arc<dyn ProductQuicInterface>,
    ifaces: Arc<DashMap<BindAddr, BoundInterface>>,
    servers: Arc<DashMap<String, Server>>,
    backlog: Arc<Semaphore>,
    #[allow(clippy::type_complexity)]
    incomings: Arc<Incomings>,

    token_provider: Arc<dyn TokenProvider>,
    parameters: ServerParameters,
    silent_rejection: bool,
    client_authers: Vec<Arc<dyn AuthClient>>,
    tls_config: TlsServerConfig,
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
        let mut global_incomings = QuicListeners::global()
            .write()
            .expect("QuicListeners global lock");
        if let Some(incomings) = global_incomings.upgrade() {
            if !incomings.is_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "A QuicServer is already running, please shutdown it first.",
                ));
            }
        }

        let incomings = Arc::new(Incomings::new(8));
        *global_incomings = Arc::downgrade(&incomings);

        Ok(QuicListenersBuilder {
            incomings,
            quic_iface_factory: Arc::new(UdpSocketController::bind),
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
    /// But the server will not be able to accept connections.
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
                        let iface = QuicInterfaces::global()
                            .insert(bind_addr.clone(), self.quic_iface_factory.clone())?;
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
    pub fn servers(&self) -> HashMap<String, HashSet<BindAddr>> {
        self.servers
            .iter()
            .map(|entry| {
                let addresses = entry
                    .value()
                    .bind_addresses
                    .iter()
                    .map(|addr| addr.key().clone())
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
    pub fn shutdown(&self) -> impl Future<Output = ()> + Send {
        let incomings = self.incomings.clone();
        let backlog = self.backlog.clone();

        async move {
            if incomings.close().is_none() {
                // already closed
                return;
            }

            Router::global()
                .register_unrouted_sink(futures::sink::drain())
                .await;

            backlog.close();
            incomings.close();
        }
    }
}

impl Drop for QuicListeners {
    fn drop(&mut self) {
        tokio::spawn(self.shutdown());
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

    fn verify_client_certs(&self, _: &str, _: Option<&str>, _: &[u8]) -> bool {
        true
    }
}

// internal methods
impl QuicListeners {
    fn global() -> &'static RwLock<Weak<Incomings>> {
        static INCOMINGS: OnceLock<RwLock<Weak<Incomings>>> = OnceLock::new();
        INCOMINGS.get_or_init(Default::default)
    }

    pub(crate) async fn try_accept_connection(
        &self,
        bind_addr: BindAddr,
        packet: Packet,
        pathway: Pathway,
        link: Link,
    ) {
        // Acquire a permit from the backlog semaphore to limit the number of concurrent connections.
        let Ok(premit) = self.backlog.clone().acquire_owned().await else {
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
            servers: self.servers.clone(),
        });

        let client_authers = [server_auther]
            .into_iter()
            .chain(self.client_authers.iter().cloned());

        let (event_broker, mut events) = mpsc::unbounded_channel();

        let connection = Arc::new(
            Connection::new_server(self.token_provider.clone())
                .with_parameters(self.parameters.clone())
                .with_silent_rejection(self.silent_rejection)
                .with_client_authers(client_authers.collect())
                .with_tls_config(self.tls_config.clone())
                .with_streams_concurrency_strategy(self.stream_strategy_factory.as_ref())
                .with_zero_rtt(self.tls_config.max_early_data_size == 0xffffffff)
                .with_defer_idle_timeout(self.defer_idle_timeout)
                .with_cids(origin_dcid, client_scid)
                .with_qlog(self.logger.clone())
                .run(event_broker),
        );

        let incomings = self.incomings.clone();

        tokio::spawn(async move {
            Router::global()
                .deliver((bind_addr.clone(), packet, pathway, link))
                .await;

            tokio::spawn({
                let connection = connection.clone();
                async move {
                    while let Some(event) = events.recv().await {
                        match event {
                            Event::Handshaked => {}
                            Event::ProbedNewPath(..) => {}
                            Event::PathInactivated(..) => {}
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
                    if incomings.send((incoming, premit)).await.is_err() {
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
}

/// The builder for the quic listeners.
pub struct QuicListenersBuilder<T> {
    quic_iface_factory: Arc<dyn ProductQuicInterface>,
    servers: Arc<DashMap<String, Server>>, // must be empty while building
    incomings: Arc<Incomings>,             // identify the building QuicListeners (TODO)

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
            quic_iface_factory: Arc::new(factory),
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
            quic_iface_factory: self.quic_iface_factory,
            servers: self.servers.clone(),
            incomings: self.incomings,
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
            quic_iface_factory: self.quic_iface_factory,
            servers: self.servers.clone(),
            incomings: self.incomings,
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
    pub async fn listen(self, backlog: usize) -> Arc<QuicListeners> {
        assert!(backlog > 0, "backlog must be greater than 0");
        debug_assert!(self.servers.is_empty());

        let quic_listeners = Arc::new(QuicListeners {
            quic_iface_factory: self.quic_iface_factory,
            ifaces: Arc::default(),
            servers: self.servers,
            backlog: Arc::new(Semaphore::new(backlog)),
            incomings: self.incomings, // any number greater than 0
            token_provider: self
                .token_provider
                .unwrap_or_else(|| Arc::new(handy::NoopTokenRegistry)),
            parameters: self.parameters,
            silent_rejection: self.silent_rejection,
            client_authers: self.client_authers,
            tls_config: self.tls_config,
            stream_strategy_factory: self.stream_strategy_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            logger: self.logger.unwrap_or_else(|| Arc::new(NoopLogger)),
            _supported_versions: self._supported_versions,
        });

        Router::global()
            .register_unrouted_sink(futures::sink::unfold(
                quic_listeners.clone(),
                |quic_listeners, (bind_addr, packet, pathway, link)| async move {
                    quic_listeners
                        .try_accept_connection(bind_addr, packet, pathway, link)
                        .await;
                    Ok(quic_listeners)
                },
            ))
            .await;

        quic_listeners
    }
}
