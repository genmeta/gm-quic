use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::{Arc, LazyLock},
};

use dashmap::DashMap;
use futures::{FutureExt, StreamExt};
use handy::Usc;
pub use qconnection::{builder::*, prelude::*};
use qlog::telemetry::{Log, handy::NullLogger};
use rustls::{
    ClientConfig as TlsClientConfig, ConfigBuilder, WantsVerifier,
    client::{ResolvesClientCert, WantsClientCert},
};
use tokio::sync::mpsc;
use tracing::{Instrument, trace_span};

use crate::{
    PROTO,
    interfaces::Interfaces,
    util::{ToCertificate, ToPrivateKey},
};

type TlsClientConfigBuilder<T> = ConfigBuilder<TlsClientConfig, T>;

/// A quic client that can initiates connections to servers.
// be different from QuicServer, QuicClient is not arc
pub struct QuicClient {
    bind_interfaces: Option<Arc<DashMap<SocketAddr, Arc<dyn QuicInterface>>>>,
    defer_idle_timeout: HeartbeatConfig,
    // TODO: 好像得创建2个quic连接，一个用ipv4，一个用ipv6
    //       然后看谁先收到服务器的响应比较好
    _enable_happy_eyepballs: bool,
    parameters: ClientParameters,
    _prefer_versions: Vec<u32>,
    quic_iface_binder: Box<dyn Fn(SocketAddr) -> io::Result<Arc<dyn QuicInterface>> + Send + Sync>,
    // TODO: 要改成一个加载上次连接的parameters的函数，根据server name
    _remembered: Option<CommonParameters>,
    reuse_connection: bool,
    reuse_interfaces: bool,
    streams_controller: Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync>,
    logger: Arc<dyn Log + Send + Sync>,
    tls_config: Arc<TlsClientConfig>,
    token_sink: Option<Arc<dyn TokenSink>>,
}

//                                        (server_name, server_addr)
static REUSEABLE_CONNECTIONS: LazyLock<DashMap<(String, SocketAddr), Arc<Connection>>> =
    LazyLock::new(DashMap::new);

impl QuicClient {
    /// Start to build a QuicClient.
    ///
    /// Make sure that you have installed the rustls crypto provider before calling this method. If you dont want to use
    /// the default crypto provider, you can use [`QuicClient::builder_with_crypto_provieder`] to specify the crypto provider.
    ///
    /// You can also use [`QuicClient::builder_with_tls`] to specify the TLS configuration.
    ///
    /// # Examples
    /// ```
    /// use gm_quic::QuicClient;
    /// use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    ///
    /// rustls::crypto::ring::default_provider()
    ///     .install_default()
    ///     .expect("Failed to install rustls crypto provider");
    ///
    /// let client_builder = QuicClient::builder()
    ///     .reuse_connection()
    ///     .prefer_versions([0x00000001u32]);
    /// ```
    pub fn builder() -> QuicClientBuilder<TlsClientConfigBuilder<WantsVerifier>> {
        QuicClientBuilder {
            bind_interfaces: Arc::new(DashMap::new()),
            reuse_interfaces: false,
            reuse_connection: false,
            enable_happy_eyepballs: false,
            prefer_versions: vec![1],
            quic_iface_binder: Box::new(|addr| Ok(Arc::new(Usc::bind(addr)?))),
            defer_idle_timeout: HeartbeatConfig::default(),
            parameters: ClientParameters::default(),
            tls_config: TlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]),
            streams_controller: Box::new(|bi, uni| Box::new(ConsistentConcurrency::new(bi, uni))),
            logger: None,
            token_sink: None,
        }
    }

    /// Start to build a QuicClient with the given tls crypto provider.
    pub fn builder_with_crypto_provieder(
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> QuicClientBuilder<TlsClientConfigBuilder<WantsVerifier>> {
        QuicClientBuilder {
            bind_interfaces: Arc::new(DashMap::new()),
            reuse_interfaces: false,
            reuse_connection: false,
            enable_happy_eyepballs: false,
            prefer_versions: vec![1],
            quic_iface_binder: Box::new(|addr| Ok(Arc::new(Usc::bind(addr)?))),
            defer_idle_timeout: HeartbeatConfig::default(),
            parameters: ClientParameters::default(),
            tls_config: TlsClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap(),
            streams_controller: Box::new(|bi, uni| Box::new(ConsistentConcurrency::new(bi, uni))),
            logger: None,
            token_sink: None,
        }
    }

    /// Start to build a QuicClient with the given TLS configuration.
    ///
    /// This is useful when you want to customize the TLS configuration, or integrate qm-quic with other crates.
    pub fn builder_with_tls(tls_config: TlsClientConfig) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_interfaces: Arc::new(DashMap::new()),
            reuse_interfaces: false,
            reuse_connection: false,
            enable_happy_eyepballs: false,
            prefer_versions: vec![1],
            defer_idle_timeout: HeartbeatConfig::default(),
            quic_iface_binder: Box::new(|addr| Ok(Arc::new(Usc::bind(addr)?))),
            parameters: ClientParameters::default(),
            tls_config,
            streams_controller: Box::new(|bi, uni| Box::new(ConsistentConcurrency::new(bi, uni))),
            logger: None,
            token_sink: None,
        }
    }

    fn new_connection(
        &self,
        server_name: String,
        server_addr: SocketAddr,
    ) -> io::Result<Arc<Connection>> {
        let quic_iface = match &self.bind_interfaces {
            None => {
                let quic_iface = if server_addr.is_ipv4() {
                    (self.quic_iface_binder)(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?
                } else {
                    (self.quic_iface_binder)(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))?
                };
                Interfaces::add(quic_iface.clone())?;
                quic_iface
            }
            Some(bind_interfaces) => {
                let no_available_address = || {
                    let mut reason = String::from("No address matches the server's address family");
                    if !self.reuse_interfaces {
                        reason
                            .push_str(", or all the bound addresses are used by other connections");
                    }
                    io::Error::new(io::ErrorKind::AddrNotAvailable, reason)
                };
                bind_interfaces
                    .iter()
                    .map(|entry| *entry.key())
                    .filter(|local_addr| local_addr.is_ipv4() == server_addr.is_ipv4())
                    .find_map(|local_addr| {
                        if self.reuse_interfaces {
                            Interfaces::try_acquire_shared(local_addr)
                        } else {
                            Interfaces::try_acquire_unique(local_addr)
                        }
                    })
                    .ok_or_else(no_available_address)?
            }
        };

        let local_addr = quic_iface.local_addr()?;
        let socket = Socket::new(local_addr, server_addr);
        let pathway = Pathway::new(
            EndpointAddr::Direct { addr: local_addr },
            EndpointAddr::Direct { addr: server_addr },
        );

        let token_sink = self
            .token_sink
            .clone()
            .unwrap_or_else(|| Arc::new(NoopTokenRegistry));

        let (event_broker, mut events) = mpsc::unbounded_channel();

        let connection = Arc::new(
            Connection::with_token_sink(server_name.clone(), token_sink)
                .with_parameters(self.parameters, None)
                .with_tls_config(self.tls_config.clone())
                .with_streams_ctrl(&self.streams_controller)
                .with_proto(PROTO.clone())
                .defer_idle_timeout(self.defer_idle_timeout)
                .with_cids(ConnectionId::random_gen(8))
                .with_qlog(self.logger.as_ref())
                .run_with(event_broker),
        );

        tokio::spawn(
            {
                let connection = connection.clone();
                async move {
                    while let Some(event) = events.recv().await {
                        match event {
                            Event::Handshaked => {}
                            Event::ProbedNewPath(_, _) => {}
                            Event::PathInactivated(_pathway, socket) => {
                                _ = Interfaces::try_free_interface(socket.src())
                            }
                            Event::Failed(error) => {
                                REUSEABLE_CONNECTIONS
                                    .remove_if(&(server_name.clone(), server_addr), |_, exist| {
                                        Arc::ptr_eq(&connection, exist)
                                    });
                                connection.enter_closing(error.into())
                            }
                            Event::Closed(ccf) => {
                                REUSEABLE_CONNECTIONS
                                    .remove_if(&(server_name.clone(), server_addr), |_, exist| {
                                        Arc::ptr_eq(&connection, exist)
                                    });
                                connection.enter_draining(ccf)
                            }
                            Event::StatelessReset => {}
                            Event::Terminated => {}
                        }
                    }
                }
            }
            .instrument(trace_span!("client_connection_driver")),
        );

        connection.add_path(socket, pathway)?;
        Ok(connection)
    }

    /// Returns the connection to the specified server.
    ///
    /// `server_name` is the name of the server, it will be included in the `ClientHello` message.
    ///
    /// `server_addr` is the address of the server, packets will be sent to this address.
    ///
    /// Note that the returned connection may not yet be connected to the server, but you can use it to do anything you
    /// want, such as sending data, receiving data... operations will be pending until the connection is connected or
    /// failed to connect.
    ///
    /// ### Select an interface
    ///
    /// First, the client will select an interface to communicate with the server.
    ///
    /// If the client has already bound a set of addresses, The client will select the interface whose IP family of the
    /// first address matches the server addr from the bound and not closed interfaces.
    ///
    /// If `reuse_interfaces` is not enabled; the client will not select an interface that is in use.
    ///
    /// ### Connecte to server
    ///
    /// If connection reuse is enabled, the client will give priority to returning the existing connection to the
    /// `server_name` and `server_addr`.
    ///
    /// If the client does not bind any interface, the client will bind the interface on the address/port randomly assigned
    /// by the system (i.e. xxx) through `quic_iface_binder` *every time* it establishes a connection. When no interface is
    /// bound, the reuse interface option will have no effect.
    ///
    /// If `reuse connection` is not enabled or there is no connection that can be reused, the client will initiates
    /// a new connection to the server.
    pub fn connect(
        &self,
        server_name: impl Into<String>,
        server_addr: SocketAddr,
    ) -> io::Result<Arc<Connection>> {
        let server_name = server_name.into();
        trace_span!("connect", %server_name,%server_addr).in_scope(|| {
            if self.reuse_connection {
                REUSEABLE_CONNECTIONS
                    .entry((server_name.clone(), server_addr))
                    .or_try_insert_with(|| self.new_connection(server_name, server_addr))
                    .map(|entry| entry.clone())
            } else {
                self.new_connection(server_name, server_addr)
            }
        })
    }
}

impl Drop for QuicClient {
    fn drop(&mut self) {
        if let Some(bind_interfaces) = self.bind_interfaces.take() {
            for entry in bind_interfaces.iter() {
                Interfaces::del(*entry.key(), entry.value());
            }
            bind_interfaces.clear();
        }
    }
}

/// A builder for [`QuicClient`].
pub struct QuicClientBuilder<T> {
    bind_interfaces: Arc<DashMap<SocketAddr, Arc<dyn QuicInterface>>>,
    reuse_interfaces: bool,
    reuse_connection: bool,
    enable_happy_eyepballs: bool,
    prefer_versions: Vec<u32>,
    quic_iface_binder: Box<dyn Fn(SocketAddr) -> io::Result<Arc<dyn QuicInterface>> + Send + Sync>,
    defer_idle_timeout: HeartbeatConfig,
    parameters: ClientParameters,
    tls_config: T,
    streams_controller: Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync>,
    logger: Option<Arc<dyn Log + Send + Sync>>,
    token_sink: Option<Arc<dyn TokenSink>>,
}

impl<T> QuicClientBuilder<T> {
    /// Specify how client bind interfaces.
    ///
    /// The given closure will be used by [`Self::bind`],
    /// and/or [`QuicClient::connect`] if no interface bound when client built.
    ///
    /// The default quic interface is [`Usc`] that support GSO and GRO,
    /// and the binder is [`Usc::bind`].
    pub fn with_iface_binder<QI, Binder>(self, binder: Binder) -> Self
    where
        QI: QuicInterface + 'static,
        Binder: Fn(SocketAddr) -> io::Result<QI> + Send + Sync + 'static,
    {
        Self {
            quic_iface_binder: Box::new(move |addr| Ok(Arc::new(binder(addr)?))),
            ..self
        }
    }

    /// Create quic interfaces bound on given address.
    ///
    /// If the bind failed, the error will be returned immediately.
    ///
    /// The default quic interface is [`Usc`] that support GSO and GRO.
    /// You can let the client bind custom interfaces by calling the [`Self::with_iface_binder`] method.
    ///
    /// If you dont bind any address, each time the client initiates a new connection,
    /// the client will use bind a new interface on address and port that dynamic assigned by the system.
    ///
    /// To know more about how the client selects the interface when initiates a new connection,
    /// read [`QuicClient::connect`].
    ///
    /// If you call this multiple times, only the last set of interface will be used,
    /// previous bound interface will be freed immediately.
    ///
    /// If the interface is closed for some reason after being created (meaning [`QuicInterface::poll_recv`]
    /// returns an error), only the log will be printed.
    ///
    /// If all interfaces are closed, clients will no longer be able to initiate new connections.
    pub fn bind(self, addrs: impl ToSocketAddrs) -> io::Result<Self> {
        for entry in self.bind_interfaces.iter() {
            Interfaces::del(*entry.key(), entry.value());
        }
        self.bind_interfaces.clear();

        let iface_recv_tasks =
            addrs
                .to_socket_addrs()?
                .try_fold(vec![], |mut recv_tasks, address| {
                    if self.bind_interfaces.contains_key(&address) {
                        return io::Result::Ok(recv_tasks);
                    }
                    let interface = (self.quic_iface_binder)(address)?;
                    let local_addr = interface.local_addr()?;
                    recv_tasks.push(
                        Interfaces::add(interface.clone())?.map(move |result| (result, local_addr)),
                    );
                    self.bind_interfaces.insert(local_addr, interface);
                    Ok(recv_tasks)
                })?;

        tokio::spawn({
            let bind_interfaces = self.bind_interfaces.clone();
            async move {
                let mut iface_recv_tasks =
                    futures::stream::FuturesUnordered::from_iter(iface_recv_tasks);
                while let Some((result, local_addr)) = iface_recv_tasks.next().await {
                    let error = match result {
                        // Ok(result) => result.into_err(),
                        Ok(error) => error,
                        Err(join_error) if join_error.is_cancelled() => return,
                        Err(join_error) => join_error.into(),
                    };
                    tracing::warn!(
                        "interface on {local_addr} that client bound was closed unexpectedly: {error}"
                    );
                    bind_interfaces.remove(&local_addr);
                }
                tracing::warn!(
                    "all interfaces that client bound were closed unexpectedly, client will not be able to connect to the server"
                );
            }
        });
        Ok(self)
    }

    /// Enable efficiently reuse connections.
    ///
    /// If you enable this option the client will give priority to returning the existing connection to the `server_name`
    /// and `server_addr`, instead of creating a new connection every time.
    pub fn reuse_connection(mut self) -> Self {
        self.reuse_connection = true;
        self
    }

    /// Enable reuse interface.
    ///
    /// If you dont bind any address, this option will not take effect.
    ///
    /// By default, the client will not use the same interface with other connections, which means that the client must
    /// select a new interface every time it initiates a connection. If you enable this option, the client will share
    /// the same address between connections.
    pub fn reuse_interfaces(mut self) -> Self {
        self.reuse_interfaces = true;
        self
    }

    /// (WIP)Specify the quic versions that the client prefers.
    ///
    /// If you call this multiple times, only the last call will take effect.
    pub fn prefer_versions(mut self, versions: impl IntoIterator<Item = u32>) -> Self {
        self.prefer_versions.clear();
        self.prefer_versions.extend(versions);
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

    /// Specify the [transport parameters] for the client.
    ///
    /// If you call this multiple times, only the last `parameters` will be used.
    ///
    /// Usually, you don't need to call this method, because the client will use a set of default parameters.
    ///
    /// [transport parameters](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit)
    pub fn with_parameters(mut self, parameters: ClientParameters) -> Self {
        self.parameters = parameters;
        self
    }

    /// Specify the streams controller for the client.
    ///
    /// The streams controller is used to control the concurrency of data streams. `controller` is a closure that accept
    /// (initial maximum number of bidirectional streams, initial maximum number of unidirectional streams) configured in
    /// [transport parameters] and return a `ControlConcurrency` object.
    ///
    /// If you call this multiple times, only the last `controller` will be used.
    ///
    /// [transport parameters](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit)
    pub fn with_streams_controller(
        mut self,
        controller: Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync>,
    ) -> Self {
        self.streams_controller = controller;
        self
    }

    pub fn with_qlog(mut self, logger: Arc<dyn Log + Send + Sync>) -> Self {
        self.logger = Some(logger);
        self
    }

    /// Specify the token sink for the client.
    ///
    /// The token sink is used to storage the tokens that the client received from the server. The client will use the
    /// tokens to prove it self to the server when it reconnects to the server. read [address verification] in quic rfc
    /// for more information.
    ///
    /// [address verification](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation)
    pub fn with_token_sink(mut self, sink: Arc<dyn TokenSink>) -> Self {
        self.token_sink = Some(sink);
        self
    }
}

impl QuicClientBuilder<TlsClientConfigBuilder<WantsVerifier>> {
    /// Choose how to verify server certificates.
    ///
    /// Read [TlsClientConfigBuilder::with_root_certificates] for more information.
    pub fn with_root_certificates(
        self,
        root_store: impl Into<Arc<rustls::RootCertStore>>,
    ) -> QuicClientBuilder<TlsClientConfigBuilder<WantsClientCert>> {
        QuicClientBuilder {
            bind_interfaces: self.bind_interfaces,
            reuse_interfaces: self.reuse_interfaces,
            reuse_connection: self.reuse_connection,
            enable_happy_eyepballs: self.enable_happy_eyepballs,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_binder: self.quic_iface_binder,
            parameters: self.parameters,
            tls_config: self.tls_config.with_root_certificates(root_store),
            streams_controller: self.streams_controller,
            logger: self.logger,
            token_sink: self.token_sink,
        }
    }

    /// Choose how to verify server certificates using a webpki verifier.
    ///
    /// Read [TlsClientConfigBuilder::with_webpki_verifier] for more information.
    pub fn with_webpki_verifier(
        self,
        verifier: Arc<rustls::client::WebPkiServerVerifier>,
    ) -> QuicClientBuilder<TlsClientConfigBuilder<WantsClientCert>> {
        QuicClientBuilder {
            bind_interfaces: self.bind_interfaces,
            reuse_interfaces: self.reuse_interfaces,
            reuse_connection: self.reuse_connection,
            enable_happy_eyepballs: self.enable_happy_eyepballs,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_binder: self.quic_iface_binder,
            parameters: self.parameters,
            tls_config: self.tls_config.with_webpki_verifier(verifier),
            streams_controller: self.streams_controller,
            logger: self.logger,
            token_sink: self.token_sink,
        }
    }
}

impl QuicClientBuilder<TlsClientConfigBuilder<WantsClientCert>> {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// Read [TlsClientConfigBuilder::with_single_cert] for more information.
    pub fn with_cert(
        self,
        cert_chain: impl ToCertificate,
        key_der: impl ToPrivateKey,
    ) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_interfaces: self.bind_interfaces,
            reuse_interfaces: self.reuse_interfaces,
            reuse_connection: self.reuse_connection,
            enable_happy_eyepballs: self.enable_happy_eyepballs,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_binder: self.quic_iface_binder,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_auth_cert(cert_chain.to_certificate(), key_der.to_private_key())
                .expect("The private key was wrong encoded or failed validation"),
            streams_controller: self.streams_controller,
            logger: self.logger,
            token_sink: self.token_sink,
        }
    }

    /// Do not support client auth.
    pub fn without_cert(self) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_interfaces: self.bind_interfaces,
            reuse_interfaces: self.reuse_interfaces,
            reuse_connection: self.reuse_connection,
            enable_happy_eyepballs: self.enable_happy_eyepballs,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_binder: self.quic_iface_binder,
            parameters: self.parameters,
            tls_config: self.tls_config.with_no_client_auth(),
            streams_controller: self.streams_controller,
            logger: self.logger,
            token_sink: self.token_sink,
        }
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_cert_resolver(
        self,
        cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_interfaces: self.bind_interfaces,
            reuse_interfaces: self.reuse_interfaces,
            reuse_connection: self.reuse_connection,
            enable_happy_eyepballs: self.enable_happy_eyepballs,
            prefer_versions: self.prefer_versions,
            quic_iface_binder: self.quic_iface_binder,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: self.tls_config.with_client_cert_resolver(cert_resolver),
            streams_controller: self.streams_controller,
            logger: self.logger,
            token_sink: self.token_sink,
        }
    }
}

impl QuicClientBuilder<TlsClientConfig> {
    /// Specify the [alpn-protocol-ids] that will be sent in `ClientHello`.
    ///
    /// By default, its empty and the APLN extension wont be sent.
    ///
    /// If you call this multiple times, all the `alpn_protocol` will be used.
    ///
    /// [alpn-protocol-ids](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids)
    pub fn with_alpns(mut self, alpns: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.tls_config.alpn_protocols.extend(alpns);
        self
    }

    /// Enable the `keylog` feature.
    ///
    /// This is useful when you want to debug the TLS connection.
    ///
    /// The keylog file will be in the file that environment veriable `SSLKEYLOGFILE` pointed to.
    ///
    /// Read [`rustls::KeyLogFile`] for more information.
    pub fn with_keylog(mut self, flag: bool) -> Self {
        if flag {
            self.tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }
        self
    }

    /// Build the QuicClient, ready to initiates connect to the servers.
    pub fn build(self) -> QuicClient {
        let bind_interfaces = if self.bind_interfaces.is_empty() {
            None
        } else {
            Some(self.bind_interfaces)
        };
        QuicClient {
            bind_interfaces,
            reuse_interfaces: self.reuse_interfaces,
            reuse_connection: self.reuse_connection,
            _enable_happy_eyepballs: self.enable_happy_eyepballs,
            _prefer_versions: self.prefer_versions,
            quic_iface_binder: self.quic_iface_binder,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            // TODO: 要能加载上次连接的parameters
            _remembered: None,
            tls_config: Arc::new(self.tls_config),
            streams_controller: self.streams_controller,
            logger: self.logger.unwrap_or_else(|| Arc::new(NullLogger)),
            token_sink: self.token_sink,
        }
    }
}
