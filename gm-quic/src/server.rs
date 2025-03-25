use std::{
    collections::HashSet,
    io::{self},
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, LazyLock, RwLock, Weak},
};

use dashmap::DashMap;
use handy::Usc;
use qconnection::builder::*;
use qinterface::util::Channel;
use qlog::{
    quic::connectivity::ServerListening,
    telemetry::{Log, handy::NullLogger},
};
use rustls::{
    ConfigBuilder, ServerConfig as TlsServerConfig, WantsVerifier,
    server::{NoClientAuth, ResolvesServerCert, WantsServerCert, danger::ClientCertVerifier},
};
use tokio::sync::mpsc;

use crate::*;

type TlsServerConfigBuilder<T> = ConfigBuilder<TlsServerConfig, T>;

// 理应全局只有一个server
static SERVER: LazyLock<RwLock<Weak<QuicServer>>> = LazyLock::new(RwLock::default);

#[derive(Debug, Default)]
pub struct VirtualHosts(Arc<DashMap<String, Host>>);

impl ResolvesServerCert for VirtualHosts {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.0.get(client_hello.server_name()?).map(|host| {
            let cert =
                rustls::sign::CertifiedKey::new(host.cert_chain.clone(), host.private_key.clone());
            Arc::new(cert)
        })
    }
}

/// The quic server that can accept incoming connections.
///
/// To create a server, you need to use the [`QuicServerBuilder`] to configure the server, and then call the
/// [`QuicServerBuilder::listen`] method to start the server.
///
/// [`QuicServer`] is unique, which means that there can be only one server running at the same time. If you want to
/// start a new server, you need to drop the old server first.
///
/// [`QuicServer`] can only accept connections, dont manage the connections. You can get the incoming connection by
/// calling the [`QuicServer::accept`] method.
pub struct QuicServer {
    bind_interfaces: DashMap<SocketAddr, Arc<dyn QuicInterface>>,
    defer_idle_timeout: HeartbeatConfig,
    listener: Arc<Channel<(Arc<Connection>, Pathway)>>,
    parameters: ServerParameters,
    use_strict_mode: bool,
    stream_strategy_factory: Box<dyn ProductStreamsConcurrencyController>,
    logger: Arc<dyn Log + Send + Sync>,
    _supported_versions: Vec<u32>,
    tls_config: Arc<TlsServerConfig>,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

impl QuicServer {
    /// Start to build a QuicServer.
    pub fn builder() -> QuicServerBuilder<TlsServerConfigBuilder<WantsVerifier>> {
        QuicServerBuilder {
            use_strict_mode: false,
            supported_versions: Vec::with_capacity(2),
            defer_idle_timeout: HeartbeatConfig::default(),
            quic_iface_factory: Box::new(Usc::bind),
            parameters: ServerParameters::default(),
            tls_config: TlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]),
            stream_strategy_factory: Box::new(ConsistentConcurrency::new),
            logger: None,
            token_provider: None,
        }
    }

    /// Start to build a QuicServer with the given TLS configuration.
    ///
    /// This is useful when you want to customize the TLS configuration, or integrate qm-quic with other crates.
    pub fn builder_with_tls(tls_config: TlsServerConfig) -> QuicServerBuilder<TlsServerConfig> {
        QuicServerBuilder {
            use_strict_mode: false,
            supported_versions: Vec::with_capacity(2),
            quic_iface_factory: Box::new(Usc::bind),
            defer_idle_timeout: HeartbeatConfig::default(),
            parameters: ServerParameters::default(),
            tls_config,
            stream_strategy_factory: Box::new(ConsistentConcurrency::new),
            logger: None,
            token_provider: None,
        }
    }

    /// Start to build a QuicServer with the given tls crypto provider.
    pub fn builder_with_crypto_provieder(
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> QuicServerBuilder<TlsServerConfigBuilder<WantsVerifier>> {
        QuicServerBuilder {
            use_strict_mode: false,
            supported_versions: Vec::with_capacity(2),
            quic_iface_factory: Box::new(Usc::bind),
            defer_idle_timeout: HeartbeatConfig::default(),
            parameters: ServerParameters::default(),
            tls_config: TlsServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap(),
            stream_strategy_factory: Box::new(ConsistentConcurrency::new),
            logger: None,
            token_provider: None,
        }
    }

    /// Get the addresses that the server still listens to.
    ///
    /// The return vector may be different from the addresses you passed to the [`QuicServerBuilder::listen`] method,
    /// because the server may fail to bind to some addresses. And, while the server is running, some sockets may be
    /// closed unexpectedly.
    pub fn addresses(&self) -> HashSet<SocketAddr> {
        self.bind_interfaces
            .iter()
            .map(|entry| *entry.key())
            .collect()
    }

    /// Accept the next incoming connection.
    ///
    /// The connection accepted may still in the progress of handshake, but you can use it to do anything you want, such
    /// as sending data, receiving data... operations will be pending until the connection is connected or closed.
    ///
    /// If all listening udp sockets are closed, this method will return an error.
    pub async fn accept(&self) -> io::Result<(Arc<Connection>, Pathway)> {
        let no_address_listening = || {
            debug_assert!(!self.use_strict_mode);
            let reason = "one of the listening interface was closed unexpectedly";
            io::Error::new(io::ErrorKind::AddrNotAvailable, reason)
        };
        self.listener.recv().await.ok_or_else(no_address_listening)
    }
}

// internal methods
impl QuicServer {
    pub(crate) async fn try_accpet_connection(packet: Packet, pathway: Pathway, link: Link) {
        let Some(server) = SERVER.read().unwrap().upgrade() else {
            return;
        };

        if server.use_strict_mode && !server.bind_interfaces.contains_key(&link.src()) {
            return;
        }

        let (client_scid, origin_dcid) = match &packet {
            Packet::Data(data_packet) => match &data_packet.header {
                DataHeader::Long(LongHeader::Initial(hdr)) => (*hdr.scid(), *hdr.dcid()),
                DataHeader::Long(LongHeader::ZeroRtt(hdr)) => (*hdr.scid(), *hdr.dcid()),
                _ => return,
            },
            _ => return,
        };

        let token_provider = server
            .token_provider
            .clone()
            .unwrap_or_else(|| Arc::new(NoopTokenRegistry));

        let (event_broker, mut events) = mpsc::unbounded_channel();

        let connection = Arc::new(
            Connection::with_token_provider(token_provider)
                .with_parameters(server.parameters.clone())
                .with_tls_config(server.tls_config.clone())
                .with_streams_concurrency_strategy(server.stream_strategy_factory.as_ref())
                .with_proto(PROTO.clone())
                .defer_idle_timeout(server.defer_idle_timeout)
                .with_cids(origin_dcid, client_scid)
                .with_qlog(server.logger.as_ref())
                .run_with(event_broker),
        );
        PROTO.deliver(packet, pathway, link).await;
        _ = server.listener.send((connection.clone(), pathway));

        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                match event {
                    Event::Handshaked => {}
                    Event::ProbedNewPath(..) => {}
                    Event::PathInactivated(_, socket) => {
                        _ = Interfaces::try_free_interface(socket.src())
                    }
                    Event::Failed(error) => connection.enter_closing(error.into()),
                    Event::Closed(ccf) => connection.enter_draining(ccf),
                    Event::StatelessReset => { /* TOOD: stateless reset */ }
                    Event::Terminated => return,
                }
            }
        });
    }

    pub fn shutdown(&self) {
        if self.listener.close().is_none() {
            // already closed
            return;
        }
        for entry in self.bind_interfaces.iter() {
            Interfaces::del(*entry.key(), entry.value());
        }
        self.bind_interfaces.clear();
    }
}

impl Drop for QuicServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Debug)]
struct Host {
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: Arc<dyn rustls::sign::SigningKey>,
}

/// The builder for the quic server.
pub struct QuicServerBuilder<T> {
    supported_versions: Vec<u32>,
    use_strict_mode: bool,
    quic_iface_factory: Box<dyn ProductQuicInterface>,
    defer_idle_timeout: HeartbeatConfig,
    parameters: ServerParameters,
    tls_config: T,
    stream_strategy_factory: Box<dyn ProductStreamsConcurrencyController>,
    logger: Option<Arc<dyn Log + Send + Sync>>,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

/// The builder for the quic server with SNI enabled.
pub struct QuicServerSniBuilder<T> {
    supported_versions: Vec<u32>,
    use_strict_mode: bool,
    hosts: Arc<DashMap<String, Host>>,
    quic_iface_factory: Box<dyn ProductQuicInterface>,
    defer_idle_timeout: HeartbeatConfig,
    parameters: ServerParameters,
    tls_config: T,
    stream_strategy_factory: Box<dyn ProductStreamsConcurrencyController>,
    logger: Option<Arc<dyn Log + Send + Sync>>,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

impl<T> QuicServerBuilder<T> {
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

    /// Specify the streams concurrency strategy controller for the server.
    ///
    /// The streams controller is used to control the concurrency of data streams. `controller` is a closure that accept
    /// (initial maximum number of bidirectional streams, initial maximum number of unidirectional streams) configured in
    /// [transport parameters] and return a `ControlConcurrency` object.
    ///
    /// If you call this multiple times, only the last `controller` will be used.
    ///
    /// [transport parameters](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit)
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

    /// Specify the [transport parameters] for the server.
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

    /// Accept connections from addresses that server not listened to.
    ///
    /// ## If the strict mode is not used (default)
    ///
    /// QuicServer will not only accept connections from the address it is bound to, it will also accept connections
    /// from all addresses that gm-quic is bound to (such as the address that [`QuicClient`] is bound to).
    ///
    /// For example, you started a client and connected to a remote server. If the strict mode is not used,
    /// the server can accept the connections that connected to the addresses that client used.
    /// This is useful in some cases, such as the server is behind a NAT.
    ///
    /// ## If the strict mode is used
    ///
    /// The server will *only* accept connections from the given addresses that successfully bound.
    pub fn use_strict_mode(mut self) -> Self {
        self.use_strict_mode = true;
        self
    }

    /// Specify how [`QuicServerBuilder::listen`] binds to the interface.
    ///
    /// The default quic interface is [`Usc`] that support GSO and GRO,
    /// and the binder is [`Usc::bind`].
    pub fn with_iface_factory<F>(self, factory: impl ProductQuicInterface + 'static) -> Self {
        Self {
            quic_iface_factory: Box::new(factory),
            ..self
        }
    }

    pub fn with_qlog(mut self, logger: Arc<dyn Log + Send + Sync>) -> Self {
        self.logger = Some(logger);
        self
    }
}

impl QuicServerBuilder<TlsServerConfigBuilder<WantsVerifier>> {
    /// Choose how to verify client certificates.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn ClientCertVerifier>,
    ) -> QuicServerBuilder<TlsServerConfigBuilder<WantsServerCert>> {
        QuicServerBuilder {
            use_strict_mode: self.use_strict_mode,
            supported_versions: self.supported_versions,
            quic_iface_factory: self.quic_iface_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_cert_verifier(client_cert_verifier),
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger,
            token_provider: self.token_provider,
        }
    }

    /// Disable client authentication.
    pub fn without_client_cert_verifier(
        self,
    ) -> QuicServerBuilder<TlsServerConfigBuilder<WantsServerCert>> {
        QuicServerBuilder {
            use_strict_mode: self.use_strict_mode,
            supported_versions: self.supported_versions,
            quic_iface_factory: self.quic_iface_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_cert_verifier(Arc::new(NoClientAuth)),
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger,
            token_provider: self.token_provider,
        }
    }
}

impl QuicServerBuilder<TlsServerConfigBuilder<WantsServerCert>> {
    /// Sets a single certificate chain and matching private key.  This
    /// certificate and key is used for all subsequent connections,
    /// irrespective of things like SNI hostname.
    ///
    /// Read [`TlsServerConfigBuilder::with_single_cert`] for more.
    pub fn with_single_cert(
        self,
        cert_chain: impl ToCertificate,
        key_der: impl ToPrivateKey,
    ) -> QuicServerBuilder<TlsServerConfig> {
        QuicServerBuilder {
            use_strict_mode: self.use_strict_mode,
            supported_versions: self.supported_versions,
            quic_iface_factory: self.quic_iface_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_single_cert(cert_chain.to_certificate(), key_der.to_private_key())
                .expect("The private key was wrong encoded or failed validation"),
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger,
            token_provider: self.token_provider,
        }
    }

    /// Sets a single certificate chain, matching private key and optional OCSP
    /// response.  This certificate and key is used for all
    /// subsequent connections, irrespective of things like SNI hostname.
    ///
    /// Read [`TlsServerConfigBuilder::with_single_cert_with_ocsp`] for more.
    pub fn with_single_cert_with_ocsp(
        self,
        cert_chain: impl ToCertificate,
        key_der: impl ToPrivateKey,
        ocsp: Vec<u8>,
    ) -> QuicServerBuilder<TlsServerConfig> {
        QuicServerBuilder {
            use_strict_mode: self.use_strict_mode,
            supported_versions: self.supported_versions,
            quic_iface_factory: self.quic_iface_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_single_cert_with_ocsp(
                    cert_chain.to_certificate(),
                    key_der.to_private_key(),
                    ocsp,
                )
                .expect("The private key was wrong encoded or failed validation"),
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger,
            token_provider: self.token_provider,
        }
    }

    /// Enable TLS SNI (Server Name Indication) extensions.
    pub fn enable_sni(self) -> QuicServerSniBuilder<TlsServerConfig> {
        let hosts = Arc::new(DashMap::new());
        QuicServerSniBuilder {
            use_strict_mode: self.use_strict_mode,
            supported_versions: self.supported_versions,
            quic_iface_factory: self.quic_iface_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_cert_resolver(Arc::new(VirtualHosts(hosts.clone()))),
            hosts,
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger,
            token_provider: self.token_provider,
        }
    }
}

impl QuicServerSniBuilder<TlsServerConfig> {
    /// Add a host with a certificate chain and a private key.
    ///
    /// Call this method multiple times to add multiple hosts, each with its own certificate chain and private key.
    /// The server will use the certificate chain and private key that matches the SNI hostname in the client's
    /// `ClientHello` message. If the client does not send an SNI hostname, or the server name don't match any host,
    /// the connection will be rejected.
    pub fn add_host(
        self,
        server_name: impl Into<String>,
        cert_chain: impl ToCertificate,
        key_der: impl ToPrivateKey,
    ) -> Self {
        let private_key = self
            .tls_config
            .crypto_provider()
            .key_provider
            .load_private_key(key_der.to_private_key())
            .unwrap();

        let server_name = server_name.into();
        self.hosts.insert(
            server_name,
            Host {
                cert_chain: cert_chain.to_certificate(),
                private_key,
            },
        );
        self
    }
}

impl QuicServerBuilder<TlsServerConfig> {
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

    /// Start to listen for incoming connections.
    ///
    /// The server will bind to all the addresses you provide and accept QUIC connections from them.
    ///
    /// If *any* address fails to bind, this method will immediately return an error and the server will not be started.
    ///
    /// The server will automatically perform the QUIC protocol handshake, and you can get the connection accepted by
    /// the server by calling the [`QuicServer::accept`] method (even though the handshake may not have been completed yet)
    ///
    /// Note that there can be only one server running at the same time,
    /// so this method will return an error if there is already a server running.
    ///
    /// When the `QuicServer` is dropped, the server will stop listening for incoming connections,
    /// and you can start a new server by calling the [`QuicServerBuilder::listen`] method again.
    ///
    /// ## If the strict mode is used
    ///
    /// The server will *only* accept connections from the given addresses that successfully bound.
    ///
    /// ## If the strict mode is not used (default)
    ///
    /// QuicServer will not only accept connections from the address it is bound to, it will also accept connections
    /// from all addresses that gm-quic is bound to (such as the address that [`QuicClient`] is bound to).
    ///
    /// If you're not using strict mode, you can even have quicServer not bind to any address here.
    pub fn listen(self, addresses: impl ToSocketAddrs) -> io::Result<Arc<QuicServer>> {
        let mut server = SERVER.write().unwrap();
        if let Some(server) = server.upgrade() {
            if !server.listener.is_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "There is already a active server running",
                ));
            }
        }

        // 不接受出现错误，出现错误直接让listen返回Err
        let (bind_interfaces, iface_recv_tasks, local_addrs) =
            addresses.to_socket_addrs()?.try_fold(
                (DashMap::new(), vec![], vec![]),
                |(bind_interfaces, mut recv_tasks, mut local_addrs), address| {
                    if bind_interfaces.contains_key(&address) {
                        return io::Result::Ok((bind_interfaces, recv_tasks, local_addrs));
                    }
                    let interface = self.quic_iface_factory.bind(address)?;
                    let local_addr = interface.local_addr()?;
                    recv_tasks.push(Interfaces::add(interface.clone())?);
                    local_addrs.push(local_addr);
                    bind_interfaces.insert(local_addr, interface);
                    qlog::event!(
                        ServerListening {
                            socket_addr: local_addr,
                        },
                        use_strict_mode = self.use_strict_mode,
                    );
                    Ok((bind_interfaces, recv_tasks, local_addrs))
                },
            )?;

        if bind_interfaces.is_empty() && self.use_strict_mode {
            let error = "no address provided, and strict mode is used";
            let error = io::Error::new(io::ErrorKind::AddrNotAvailable, error);
            return Err(error);
        }

        let quic_server = Arc::new(QuicServer {
            bind_interfaces,
            use_strict_mode: self.use_strict_mode,
            listener: Default::default(),
            _supported_versions: self.supported_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: Arc::new(self.tls_config),
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger.unwrap_or_else(|| Arc::new(NullLogger)),
            token_provider: self.token_provider,
        });

        tokio::spawn({
            let server = quic_server.clone();
            async move {
                let (result, iface_idx, _) = futures::future::select_all(iface_recv_tasks).await;
                let error = match result {
                    Ok(error) => error,
                    Err(_join_error) if server.listener.is_closed() => return,
                    Err(join_error) => join_error.into(),
                };
                let local_addr = local_addrs[iface_idx];
                tracing::error!(
                    "interface on {local_addr} that server listened was closed unexpectedly: {error}"
                );
                server.shutdown();
            }
        });

        *server = Arc::downgrade(&quic_server);
        Ok(quic_server)
    }
}

impl QuicServerSniBuilder<TlsServerConfig> {
    /// Specify the `alpn_protocol` that the server supports.
    ///
    /// If you call this multiple times, all the `alpn_protocol` will be used.
    ///
    /// If you never call this method, we will not do ALPN negotiation with the client.
    pub fn with_alpns(mut self, alpn: impl IntoIterator<Item = impl Into<Vec<u8>>>) -> Self {
        self.tls_config
            .alpn_protocols
            .extend(alpn.into_iter().map(Into::into));
        self
    }

    /// Start to listen for incoming connections.
    ///
    /// The server will bind to all the addresses you provide and accept QUIC connections from them.
    ///
    /// If *any* address fails to bind, this method will immediately return an error and the server will not be started.
    ///
    /// The server will automatically perform the QUIC protocol handshake, and you can get the connection accepted by
    /// the server by calling the [`QuicServer::accept`] method (even though the handshake may not have been completed yet)
    ///
    /// Note that there can be only one server running at the same time,
    /// so this method will return an error if there is already a server running.
    ///
    /// When the `QuicServer` is dropped, the server will stop listening for incoming connections,
    /// and you can start a new server by calling the [`QuicServerBuilder::listen`] method again.
    ///
    /// ## If the strict mode is used
    ///
    /// The server will *only* accept connections from the given addresses that successfully bound.
    ///
    /// ## If the strict mode is not used (default)
    ///
    /// QuicServer will not only accept connections from the address it is bound to, it will also accept connections
    /// from all addresses that gm-quic is bound to (such as the address that [`QuicClient`] is bound to).
    ///
    /// For example, you started a client and connected to a remote server. If the strict mode is not used,
    /// the server can accept the connections that connected to the addresses that client used.
    /// This is useful in some cases, such as the server is behind a NAT.
    ///
    /// If you're not using strict mode, you can even have quicServer not bind to any address here.
    pub fn listen(self, addresses: impl ToSocketAddrs) -> io::Result<Arc<QuicServer>> {
        let mut server = SERVER.write().unwrap();
        if let Some(server) = server.upgrade() {
            if !server.listener.is_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "There is already a active server running",
                ));
            }
        }

        // 不接受出现错误，出现错误直接让listen返回Err
        let (bind_interfaces, iface_recv_tasks, local_addrs) =
            addresses.to_socket_addrs()?.try_fold(
                (DashMap::new(), vec![], vec![]),
                |(bind_interfaces, mut recv_tasks, mut local_addrs), address| {
                    if bind_interfaces.contains_key(&address) {
                        return io::Result::Ok((bind_interfaces, recv_tasks, local_addrs));
                    }
                    let interface = self.quic_iface_factory.bind(address)?;
                    let local_addr = interface.local_addr()?;
                    recv_tasks.push(Interfaces::add(interface.clone())?);
                    local_addrs.push(local_addr);
                    bind_interfaces.insert(local_addr, interface);
                    qlog::event!(
                        ServerListening {
                            socket_addr: local_addr,
                        },
                        use_strict_mode = self.use_strict_mode,
                    );
                    Ok((bind_interfaces, recv_tasks, local_addrs))
                },
            )?;

        if bind_interfaces.is_empty() && self.use_strict_mode {
            let error = "no address provided, and strict mode is used";
            let error = io::Error::new(io::ErrorKind::AddrNotAvailable, error);
            return Err(error);
        }

        let quic_server = Arc::new(QuicServer {
            bind_interfaces,
            use_strict_mode: self.use_strict_mode,
            listener: Default::default(),
            _supported_versions: self.supported_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: Arc::new(self.tls_config),
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger.unwrap_or_else(|| Arc::new(NullLogger)),
            token_provider: self.token_provider,
        });

        tokio::spawn({
            let server = quic_server.clone();
            async move {
                let (result, iface_idx, _) = futures::future::select_all(iface_recv_tasks).await;
                let error = match result {
                    Ok(error) => error,
                    Err(_join_error) if server.listener.is_closed() => return,
                    Err(join_error) => join_error.into(),
                };
                let local_addr = local_addrs[iface_idx];
                tracing::error!(
                    "interface on {local_addr} that server listened was closed unexpectedly: {error}"
                );
                server.shutdown();
            }
        });

        *server = Arc::downgrade(&quic_server);
        Ok(quic_server)
    }
}
