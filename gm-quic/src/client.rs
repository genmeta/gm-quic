use std::{io, str::FromStr, sync::Arc, time::Duration};

use dashmap::DashMap;
use qbase::net::{
    Family,
    addr::{AddrKind, BindUri},
};
use qconnection::{builder::*, prelude::handy::*};
use qevent::telemetry::{Log, handy::NoopLogger};
use qinterface::{
    factory::ProductQuicIO,
    iface::{BindInterface, QuicInterfaces},
};
use rustls::{
    ConfigBuilder, WantsVerifier,
    client::{ResolvesClientCert, WantsClientCert},
};
use thiserror::Error;

use crate::*;

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
    pub fn builder_with_crypto_provieder(
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
            bind_interfaces: DashMap::new(),
            prefer_versions: vec![1],
            defer_idle_timeout: Duration::ZERO,
            quic_iface_factory: Arc::new(handy::DEFAULT_QUIC_IO_FACTORY),
            parameters: handy::client_parameters(),
            tls_config,
            stream_strategy_factory: Box::new(ConsistentConcurrency::new),
            logger: None,
            token_sink: None,
        }
    }
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
    /// Returns the connection to the specified server.
    ///
    /// `server_name` is the name of the server, it will be included in the `ClientHello` message.
    ///
    /// `server_addr` is the address of the server, packets will be sent to this address.
    ///
    /// Note that the returned connection may not yet be connected to the server, but you can use it to do anything you want,
    /// such as sending data, receiving data... operations will be pending until the connection is connected or failed to connect.
    ///
    /// ### Create paths
    ///
    /// If the client binds some addresses during construction,
    /// the client will try to use the available addresses to pair with the addresses of each server to create multiple paths.
    ///
    /// If the client does not bind an address during construction,
    /// the client will try to bind some random addresses based on the type of server address to create paths.
    ///
    /// This method returns an error only if binding a new interface fails.
    ///
    /// This method may produce a connection without any path
    pub fn connect(
        &self,
        server_name: impl Into<String>,
        server_eps: impl IntoIterator<Item = impl Into<EndpointAddr>>,
    ) -> Result<Arc<Connection>, BindInterfaceError> {
        let server_name = server_name.into();
        let avaliable_ifaces = self.bind_interfaces.as_ref().map(|map| {
            map.iter()
                .filter_map(|entry| entry.value().borrow().ok())
                .filter_map(|iface| Some((iface.real_addr().ok()?, iface)))
                .collect::<Vec<_>>()
        });

        let select_or_bind_ifaces = |server_ep: &EndpointAddr| match &avaliable_ifaces {
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

        let mut paths = vec![];

        for server_ep in server_eps.into_iter().map(Into::into) {
            paths.extend(select_or_bind_ifaces(&server_ep)?.into_iter().map(
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

        let connection = Arc::new(
            Connection::new_client(server_name.clone(), self.token_sink.clone())
                .with_parameters(self.parameters.clone())
                .with_tls_config(self.tls_config.clone())
                .with_streams_concurrency_strategy(self.stream_strategy_factory.as_ref())
                .with_zero_rtt(self.tls_config.enable_early_data)
                .with_defer_idle_timeout(self.defer_idle_timeout)
                .with_cids(ConnectionId::random_gen(8))
                .with_qlog(self.logger.clone())
                .run(),
        );

        for (iface, link, pathway) in paths {
            _ = connection.add_path(iface.bind_uri(), link, pathway);
        }

        Ok(connection)
    }
}

/// A builder for [`QuicClient`].
pub struct QuicClientBuilder<T> {
    bind_interfaces: DashMap<BindUri, BindInterface>,
    prefer_versions: Vec<u32>,
    quic_iface_factory: Arc<dyn ProductQuicIO>,
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
    pub fn bind(self, addrs: impl IntoIterator<Item = impl Into<BindUri>>) -> Self {
        self.bind_interfaces.clear();

        for bind_uri in addrs.into_iter().map(Into::into) {
            if self.bind_interfaces.contains_key(&bind_uri) {
                continue;
            }
            let interface =
                QuicInterfaces::global().bind(bind_uri.clone(), self.quic_iface_factory.clone());
            self.bind_interfaces.insert(bind_uri, interface);
        }

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
            bind_interfaces: self.bind_interfaces,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_factory: self.quic_iface_factory,
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
            bind_interfaces: self.bind_interfaces,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_factory: self.quic_iface_factory,
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
            bind_interfaces: self.bind_interfaces,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_factory: self.quic_iface_factory,
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
        cert_chain: impl ToCertificate,
        key_der: impl ToPrivateKey,
    ) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_interfaces: self.bind_interfaces,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_factory: self.quic_iface_factory,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_auth_cert(cert_chain.to_certificate(), key_der.to_private_key())
                .expect("The private key was wrong encoded or failed validation"),
            stream_strategy_factory: self.stream_strategy_factory,
            logger: self.logger,
            token_sink: self.token_sink,
        }
    }

    /// Do not support client auth.
    pub fn without_cert(self) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_interfaces: self.bind_interfaces,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            quic_iface_factory: self.quic_iface_factory,
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
            bind_interfaces: self.bind_interfaces,
            prefer_versions: self.prefer_versions,
            quic_iface_factory: self.quic_iface_factory,
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
        let bind_interfaces = if self.bind_interfaces.is_empty() {
            None
        } else {
            Some(self.bind_interfaces)
        };
        QuicClient {
            bind_interfaces,
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
