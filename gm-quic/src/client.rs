use std::{collections::HashMap, io, str::FromStr, sync::Arc, time::Duration};

use dashmap::DashMap;
use qbase::{
    net::{
        Family,
        addr::{AddrKind, BindUri},
    },
    param::ClientParameters,
    token::TokenSink,
};
use qconnection::prelude::handy::*;
use qevent::telemetry::{Log, handy::NoopLogger};
use qinterface::{
    factory::ProductQuicIO,
    logical::{BindInterface, QuicInterface, QuicInterfaces},
};
use rustls::{
    ConfigBuilder, WantsVerifier,
    client::{ResolvesClientCert, WantsClientCert},
};
use thiserror::Error;

use crate::{prelude::*, *};

type TlsClientConfig = rustls::ClientConfig;
type TlsClientConfigBuilder<T> = ConfigBuilder<TlsClientConfig, T>;

/// A QUIC client for initiating connections to servers.
///
/// ## Creating Clients
///
/// Use [`QuicClient::builder`] to configure and create a client instance.
/// Configure interfaces, TLS settings, and connection behavior before building.
///
/// ## Interface Management
///
/// - **Automatic binding**: If no interfaces are bound, the client automatically binds to system-assigned addresses
/// - **Manual binding**: Use [`QuicClientBuilder::bind`] to bind specific interfaces
///
/// ## Connection Handling
///
/// Call [`QuicClient::connect`] to establish connections. The client supports:
/// - **Automatic interface selection**: Matches interface with server endpoint address
pub struct QuicClient {
    bind_interfaces: Option<DashMap<BindUri, BindInterface>>,
    defer_idle_timeout: Duration,
    parameters: ClientParameters,
    _prefer_versions: Vec<u32>,
    quic_iface_factory: Arc<dyn ProductQuicIO>,
    stream_strategy_factory: Box<dyn ProductStreamsConcurrencyController>,
    logger: Arc<dyn Log + Send + Sync>,
    tls_config: TlsClientConfig,
    token_sink: Arc<dyn TokenSink>,
}

impl QuicClient {
    /// Create a new [`QuicClient`] builder.
    pub fn builder() -> QuicClientBuilder<TlsClientConfigBuilder<WantsVerifier>> {
        Self::builder_with_tls(TlsClientConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS13,
        ]))
    }

    /// Create a [`QuicClient`] builder with custom crypto provider.
    pub fn builder_with_crypto_provider(
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> QuicClientBuilder<TlsClientConfigBuilder<WantsVerifier>> {
        Self::builder_with_tls(
            TlsClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap(),
        )
    }

    /// Start to build a QuicClient with the given TLS configuration.
    ///
    /// This is useful when you want to customize the TLS configuration, or integrate qm-quic with other crates.
    pub fn builder_with_tls<T>(tls_config: T) -> QuicClientBuilder<T> {
        QuicClientBuilder {
            bind_ifaces: None,
            prefer_versions: vec![1],
            defer_idle_timeout: Duration::ZERO,
            quic_iface_factory: Arc::new(handy::DEFAULT_QUIC_IO_FACTORY),
            quic_ifaces: QuicInterfaces::global().clone(),
            parameters: handy::client_parameters(),
            tls_config,
            stream_strategy_factory: Box::new(ConsistentConcurrency::new),
            logger: None,
            token_sink: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConnectServerError {
    #[error("DNS lookup failed")]
    Dns {
        #[from]
        source: io::Error,
    },
    #[error("Failed to bind interface for client connection")]
    BindInterface {
        #[from]
        source: BindInterfaceError,
    },
}

#[derive(Debug, Error)]
#[error(
    "Failed to bind interface `{}` for client connection",
    bind_uri.as_ref().map_or(String::from("<no bind uri generated>"), |bind_uri| bind_uri.to_string())
)]
pub struct BindInterfaceError {
    bind_uri: Option<BindUri>,
    #[source]
    bind_error: io::Error,
}

impl QuicClient {
    #[inline]
    pub fn bind_interfaces(&self) -> Option<HashMap<BindUri, BindInterface>> {
        self.bind_interfaces.as_ref().map(|map| {
            map.iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect()
        })
    }

    #[inline]
    pub fn add_interface(&self, interface: BindInterface) {
        if let Some(interfaces) = self.bind_interfaces.as_ref() {
            interfaces.insert(interface.bind_uri(), interface);
        }
    }

    #[inline]
    pub fn remove_interface(&self, bind_uri: &BindUri) -> Option<BindInterface> {
        self.bind_interfaces
            .as_ref()
            .and_then(|interfaces| interfaces.remove(bind_uri).map(|(_, iface)| iface))
    }

    /// Creates a new QUIC connection to the specified server without any initial paths.
    ///
    /// This method initializes the connection state but does not start the handshake
    /// because no network paths are established yet. You must manually add paths
    /// using [`Connection::add_path`] to initiate communication.
    ///
    /// This is useful for advanced scenarios where you need fine-grained control
    /// over which interfaces and paths are used for the connection.
    pub fn new_connection(&self, server_name: impl Into<String>) -> Connection {
        Connection::new_client(server_name.into(), self.token_sink.clone())
            .with_parameters(self.parameters.clone())
            .with_tls_config(self.tls_config.clone())
            .with_streams_concurrency_strategy(self.stream_strategy_factory.as_ref())
            .with_zero_rtt(self.tls_config.enable_early_data)
            .with_defer_idle_timeout(self.defer_idle_timeout)
            .with_cids(ConnectionId::random_gen(8))
            .with_qlog(self.logger.clone())
            .run()
    }

    /// Probes and generates potential network paths to the given server endpoints.
    ///
    /// This method determines which local interfaces should be used to reach the
    /// specified server addresses.
    ///
    /// - **With bound interfaces**: If the client was created with specific bound interfaces,
    ///   it attempts to pair those interfaces with the server's addresses (e.g., IPv4 to IPv4).
    /// - **Without bound interfaces**: If no interfaces were explicitly bound, the client
    ///   automatically binds to system-assigned addresses (ephemeral ports) appropriate
    ///   for the server's address family.
    ///
    /// Returns a list of tuples containing the interface, link, and pathway information
    /// needed to establish a connection path.
    ///
    /// ### Example
    ///
    /// ```no_run
    /// # use gm_quic::prelude::{QuicClient, QuicIO};
    /// # async fn example(quic_client: &QuicClient) -> Result<(), Box<dyn std::error::Error>> {
    /// let server_addresses = tokio::net::lookup_host("genmeta.net:443").await?;
    /// let paths = quic_client.probe(server_addresses).await?;
    /// let connection = quic_client.new_connection("genmeta.net");
    /// for (iface, link, pathway) in paths {
    ///     connection.add_path(iface.bind_uri(), link, pathway)?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn probe(
        &self,
        server_eps: impl IntoIterator<Item = impl Into<EndpointAddr>>,
    ) -> Result<Vec<(QuicInterface, Link, Pathway)>, BindInterfaceError> {
        let avaliable_ifaces = self.bind_interfaces.as_ref().map(|map| {
            map.iter()
                .filter_map(|entry| entry.value().borrow().ok())
                .filter_map(|iface| Some((iface.real_addr().ok()?, iface)))
                .collect::<Vec<_>>()
        });

        let select_or_bind_ifaces = async |server_ep: &EndpointAddr| match &avaliable_ifaces {
            None => {
                let bind_uri: BindUri = match server_ep.addr_kind() {
                    AddrKind::Internet(Family::V4) => BindUri::from_str("inet://0.0.0.0:0")
                        .expect("URL should be valid")
                        .alloc_port(),
                    AddrKind::Internet(Family::V6) => BindUri::from_str("inet://[::]:0")
                        .expect("URL should be valid")
                        .alloc_port(),
                    _ => {
                        return Err(BindInterfaceError {
                            bind_uri: None,
                            bind_error: io::Error::new(
                                io::ErrorKind::Unsupported,
                                "BLE and other address kinds are not supported yet",
                            ),
                        });
                    }
                };
                let iface = QuicInterfaces::global()
                    .bind(bind_uri.clone(), self.quic_iface_factory.clone())
                    .await
                    .borrow()
                    .and_then(|iface| Ok((iface.real_addr()?, iface)))
                    .map_err(|source| BindInterfaceError {
                        bind_uri: Some(bind_uri),
                        bind_error: source,
                    })?;
                Ok(vec![iface])
            }
            Some(bind_interfaces) => {
                let ifaces = bind_interfaces
                    .iter()
                    .filter(|(addr, _)| addr.kind() == server_ep.addr_kind())
                    .cloned()
                    .collect::<Vec<_>>();
                Ok(ifaces)
            }
        };

        let server_eps = server_eps.into_iter().map(Into::into).collect::<Vec<_>>();

        let mut paths = vec![];
        for &server_ep in &server_eps {
            if matches!(
                server_ep,
                EndpointAddr::Socket(SocketEndpointAddr::Agent { .. })
            ) {
                continue;
            }
            paths.extend(select_or_bind_ifaces(&server_ep).await?.into_iter().map(
                move |(real_addr, iface)| {
                    let dst = match server_ep {
                        EndpointAddr::Socket(socket_endpoint_addr) => {
                            RealAddr::Internet(*socket_endpoint_addr)
                        }
                        EndpointAddr::Ble(ble_endpont_addr) => {
                            RealAddr::Bluetooth(*ble_endpont_addr)
                        }
                    };
                    let link = Link::new(real_addr, dst);
                    let pathway = Pathway::new(real_addr.into(), server_ep);
                    (iface, link, pathway)
                },
            ));
        }

        Ok(paths)
    }

    /// Connects to a server using specific endpoint addresses.
    ///
    /// This method combines [`QuicClient::probe`] and [`QuicClient::new_connection`].
    /// It creates a connection and automatically adds paths for all the provided
    /// server endpoints.
    ///
    /// The returned [`Connection`] may not have completed the handshake yet.
    /// However, any asynchronous operations on the connection (like opening streams)
    /// will automatically wait for the handshake to complete.
    ///
    /// If `server_eps` is empty, this is equivalent to calling [`QuicClient::new_connection`]
    /// and the connection will remain idle until paths are added.
    pub async fn connected_to(
        &self,
        server_name: impl Into<String>,
        server_eps: impl IntoIterator<Item = impl Into<EndpointAddr>>,
    ) -> Result<Connection, ConnectServerError> {
        let server_eps = server_eps.into_iter().map(Into::into).collect::<Vec<_>>();
        let paths = self
            .probe(server_eps.iter().copied())
            .await
            .map_err(|source| ConnectServerError::BindInterface { source })?;
        let connection = self.new_connection(server_name);
        for (iface, link, pathway) in paths {
            _ = connection.add_path(iface.bind_uri(), link, pathway);
        }

        _ = connection.subscribe_address();
        for server_ep in server_eps.into_iter() {
            _ = connection.add_peer_endpoint(server_ep);
        }
        Ok(connection)
    }

    /// Connects to a server by its hostname and optional port.
    ///
    /// This is the most convenient way to establish a connection. It performs the following steps:
    /// 1. Parses the server string (e.g., "example.com" or "example.com:443").
    ///    Defaults to port 443 if not specified.
    /// 2. Performs an asynchronous DNS lookup to resolve the hostname to IP addresses.
    /// 3. Calls [`QuicClient::connected_to`] with the resolved addresses.
    ///
    /// The returned [`Connection`] may not have completed the handshake yet.
    /// Asynchronous operations on the connection will wait for the handshake.
    pub fn connect<'c>(
        &'c self,
        server: &str,
    ) -> impl std::future::Future<Output = Result<Connection, ConnectServerError>> + use<'c> {
        let (server_name, port) = match server.split_once(':') {
            Some((server, port)) => match port.parse::<u16>() {
                Ok(port) => (server, port),
                Err(_invalid_port) => (server, 443),
            },
            None => (server, 443),
        };

        tracing::debug!("Connecting to {server_name}:{port}");
        let server_name = server_name.to_owned();
        async move {
            // TODO: http dns mdns
            let server_eps = tokio::net::lookup_host((server_name.as_str(), port)).await?;
            tracing::debug!(target: "h3x::client", "DNS lookup for {server_name}:{port} returned about {} addresses", server_eps.size_hint().0);
            self.connected_to(&server_name, server_eps).await
        }
    }
}

/// A builder for [`QuicClient`].
pub struct QuicClientBuilder<T> {
    quic_iface_factory: Arc<dyn ProductQuicIO>,
    quic_ifaces: Arc<QuicInterfaces>,
    bind_ifaces: Option<DashMap<BindUri, BindInterface>>,
    prefer_versions: Vec<u32>,
    defer_idle_timeout: Duration,
    parameters: ClientParameters,
    tls_config: T,
    stream_strategy_factory: Box<dyn ProductStreamsConcurrencyController>,
    logger: Option<Arc<dyn Log + Send + Sync>>,
    token_sink: Option<Arc<dyn TokenSink>>,
}

impl<T> QuicClientBuilder<T> {
    /// Specify how client bind interfaces.
    ///
    /// The given factory will be used by [`Self::bind`],
    /// and/or [`QuicClient::connect`] if no interface bound when client built.
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

    /// Create quic interfaces bound on given address.
    ///
    /// If the bind failed, the error will be returned immediately.
    ///
    /// The default quic interface is provided by [`handy::DEFAULT_QUIC_IO_FACTORY`].
    /// For Unix and Windows targets, this is a high performance UDP library supporting GSO and GRO
    /// provided by `qudp` crate. For other platforms, please specify you own factory with
    /// [`QuicClientBuilder::with_iface_factory`].
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
    /// If all interfaces are closed, clients will no longer be able to initiate new connections.
    pub async fn bind(mut self, addrs: impl IntoIterator<Item = impl Into<BindUri>>) -> Self {
        // clear previously bound interfaces
        self.bind_ifaces = None;
        let bind_ifaces = DashMap::new();

        for bind_uri in addrs.into_iter().map(Into::into) {
            if bind_ifaces.contains_key(&bind_uri) {
                continue;
            }
            let factory = self.quic_iface_factory.clone();
            let iface = self.quic_ifaces.bind(bind_uri.clone(), factory).await;
            bind_ifaces.insert(bind_uri, iface);
        }

        self.bind_ifaces = Some(bind_ifaces);
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
    pub fn defer_idle_timeout(mut self, duration: Duration) -> Self {
        self.defer_idle_timeout = duration;
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

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.parameters
            .set(ParameterId::ClientName, name.into())
            .expect("parameter 0xffee belong_to client and has type String");
        self
    }

    /// Specify the streams concurrency strategy controller for the client.
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
            bind_ifaces: self.bind_ifaces,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_factory: self.quic_iface_factory,
            quic_ifaces: self.quic_ifaces,
            parameters: self.parameters,
            tls_config: self.tls_config.with_root_certificates(root_store),
            stream_strategy_factory: self.stream_strategy_factory,
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
            bind_ifaces: self.bind_ifaces,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_factory: self.quic_iface_factory,
            quic_ifaces: self.quic_ifaces,
            parameters: self.parameters,
            tls_config: self.tls_config.with_webpki_verifier(verifier),
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger,
            token_sink: self.token_sink,
        }
    }

    /// Dangerously disable server certificate verification.
    pub fn without_verifier(self) -> QuicClientBuilder<TlsClientConfigBuilder<WantsClientCert>> {
        #[derive(Debug)]
        struct DangerousServerCertVerifier;

        impl rustls::client::danger::ServerCertVerifier for DangerousServerCertVerifier {
            fn verify_server_cert(
                &self,
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &[rustls::pki_types::CertificateDer<'_>],
                _: &rustls::pki_types::ServerName<'_>,
                _: &[u8],
                _: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::RSA_PKCS1_SHA1,
                    rustls::SignatureScheme::ECDSA_SHA1_Legacy,
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA384,
                    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                    rustls::SignatureScheme::RSA_PKCS1_SHA512,
                    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA384,
                    rustls::SignatureScheme::RSA_PSS_SHA512,
                    rustls::SignatureScheme::ED25519,
                    rustls::SignatureScheme::ED448,
                ]
            }
        }
        QuicClientBuilder {
            bind_ifaces: self.bind_ifaces,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_factory: self.quic_iface_factory,
            quic_ifaces: self.quic_ifaces,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerousServerCertVerifier)),
            stream_strategy_factory: self.stream_strategy_factory,
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
        cert: impl handy::ToCertificate,
        key: impl handy::ToPrivateKey,
    ) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_ifaces: self.bind_ifaces,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_factory: self.quic_iface_factory,
            quic_ifaces: self.quic_ifaces,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_auth_cert(cert.to_certificate(), key.to_private_key())
                .expect("The private key was wrong encoded or failed validation"),
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger,
            token_sink: self.token_sink,
        }
    }

    /// Do not support client auth.
    pub fn without_cert(self) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_ifaces: self.bind_ifaces,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_factory: self.quic_iface_factory,
            quic_ifaces: self.quic_ifaces,
            parameters: self.parameters,
            tls_config: self.tls_config.with_no_client_auth(),
            stream_strategy_factory: self.stream_strategy_factory,
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
            bind_ifaces: self.bind_ifaces,
            prefer_versions: self.prefer_versions,
            quic_iface_factory: self.quic_iface_factory,
            quic_ifaces: self.quic_ifaces,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: self.tls_config.with_client_cert_resolver(cert_resolver),
            stream_strategy_factory: self.stream_strategy_factory,
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
    pub fn with_alpns(mut self, alpns: impl IntoIterator<Item = impl Into<Vec<u8>>>) -> Self {
        self.tls_config
            .alpn_protocols
            .extend(alpns.into_iter().map(Into::into));
        self
    }

    /// Enable the `keylog` feature.
    ///
    /// This is useful when you want to debug the TLS connection.
    ///
    /// The keylog file will be in the file that environment veriable `SSLKEYLOGFILE` pointed to.
    ///
    /// Read [`rustls::KeyLogFile`] for more information.
    pub fn enable_sslkeylog(mut self) -> Self {
        self.tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        self
    }

    pub fn enable_0rtt(mut self) -> Self {
        self.tls_config.enable_early_data = true;
        self
    }

    /// Build the QuicClient, ready to initiates connect to the servers.
    pub fn build(self) -> QuicClient {
        QuicClient {
            bind_interfaces: self.bind_ifaces,
            _prefer_versions: self.prefer_versions,
            quic_iface_factory: self.quic_iface_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: self.tls_config,
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger.unwrap_or_else(|| Arc::new(NoopLogger)),
            token_sink: self.token_sink.unwrap_or(Arc::new(NoopTokenRegistry)),
        }
    }
}
