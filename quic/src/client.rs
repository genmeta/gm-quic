use std::{
    io::{self},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::Path,
    sync::Arc,
};

use qbase::{
    cid::ConnectionId,
    param::{ClientParameters, Parameters},
    sid::{handy::ConsistentConcurrency, ControlConcurrency},
    token::{ArcTokenRegistry, TokenSink},
};
use qconnection::{conn::ArcConnection, path::Pathway};
use rustls::{
    client::{ResolvesClientCert, WantsClientCert},
    pki_types::{CertificateDer, PrivateKeyDer},
    ClientConfig as TlsClientConfig, ConfigBuilder, WantsVerifier,
};

use crate::{create_new_usc, get_or_create_usc, util, ConnKey, QuicConnection, CONNECTIONS};

type TlsClientConfigBuilder<T> = ConfigBuilder<TlsClientConfig, T>;

/// A quic client that can initiates connections to servers.
pub struct QuicClient {
    bind_addresseses: Vec<SocketAddr>,
    reuse_udp_sockets: bool,
    _reuse_connection: bool, // TODO
    _enable_happy_eyepballs: bool,
    _prefer_versions: Vec<u32>,
    parameters: Parameters,
    tls_config: Arc<TlsClientConfig>,
    streams_controller: Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync>,
    token_sink: Option<Arc<dyn TokenSink>>,
}

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
    /// use quic::QuicClient;
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
            bind_addresses: vec![],
            reuse_udp_sockets: false,
            reuse_connection: true,
            enable_happy_eyepballs: false,
            prefer_versions: vec![1],
            parameters: Parameters::default(),
            tls_config: TlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]),
            streams_controller: Box::new(|bi, uni| Box::new(ConsistentConcurrency::new(bi, uni))),
            token_sink: None,
        }
    }

    /// Start to build a QuicClient with the given tls crypto provider.
    pub fn builder_with_crypto_provieder(
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> QuicClientBuilder<TlsClientConfigBuilder<WantsVerifier>> {
        QuicClientBuilder {
            bind_addresses: vec![],
            reuse_udp_sockets: false,
            reuse_connection: true,
            enable_happy_eyepballs: false,
            prefer_versions: vec![1],
            parameters: Parameters::default(),
            tls_config: TlsClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap(),
            streams_controller: Box::new(|bi, uni| Box::new(ConsistentConcurrency::new(bi, uni))),
            token_sink: None,
        }
    }

    /// Start to build a QuicClient with the given TLS configuration.
    ///
    /// This is useful when you want to customize the TLS configuration, or integrate qm-quic with other crates.
    pub fn builder_with_tls(tls_config: TlsClientConfig) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_addresses: vec![],
            reuse_udp_sockets: false,
            reuse_connection: true,
            enable_happy_eyepballs: false,
            prefer_versions: vec![1],
            parameters: Parameters::default(),
            tls_config,
            streams_controller: Box::new(|bi, uni| Box::new(ConsistentConcurrency::new(bi, uni))),
            token_sink: None,
        }
    }

    /// Rebind the client to the given addresses.
    ///
    /// New connections will be initiates with the new boudn addresses, previously created connections will not be affected.
    ///
    /// If you call this multiple times, only the last `addrs` will be used. You can pass a empty slice to clear the
    /// bound addresses, then each time the client initiates a new connection, the client will use the address and port
    /// that dynamic assigned by the system.
    ///
    /// To know more about how the client selects the socket address, read [`QuicClient::connect`].
    pub fn rebind(&mut self, addrs: impl ToSocketAddrs) -> io::Result<()> {
        self.bind_addresseses.clear();
        self.bind_addresseses.extend(addrs.to_socket_addrs()?);
        Ok(())
    }

    fn gen_cid() -> ConnectionId {
        ConnectionId::random_gen_with_mark(8, 0, 0x7F)
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
    /// ### (WIP)Reuse connection
    ///
    /// If `reuse connection` is enabled, the client will try to reuse the connection that has already connected to the
    /// server, this means that the client will not initiates a new connection, but return the existing connection.
    /// Otherwise, the client will initiates a new connection to the server.
    ///
    /// If `reuse connection` is not enabled or there is no connection that can be reused, the client will bind a UDP Socket
    /// and initiates a new connection to the server.
    ///
    /// If the client does not bind any address, Each time the client initiates a new connection, the client will use
    /// the address and port that dynamic assigned by the system.
    ///
    /// If the client has already bound a set of addresses, The client will successively try to bind to an address that
    /// matches the server's address family, until an address is successfully bound. If none of the given addresses are
    /// successfully bound, the last error will be returned (similar to `UdpSocket::bind`). Its also possiable that all
    /// of the bound addresses dont match the server's address family, an error will be returned in this case.
    ///
    /// How the client binds the address depends on whether `reuse udp sockets` is enabled.
    ///
    /// If `reuse udp sockets` is enabled, the client may share the same address with other connections. If `reuse udp
    /// sockets` is disabled (default), The client will not bind to addresses that is already used by another connection.
    ///
    /// Note that although `reuse udp sockets` is not enabled, the socket bound by the client may still be reused, because
    /// this option can only determine the behavior of this client when initiates a new connection.
    pub fn connect(
        &self,
        server_name: impl Into<String>,
        server_addr: SocketAddr,
    ) -> io::Result<Arc<QuicConnection>> {
        let server_name = server_name.into();

        let usc_creator = if self.reuse_udp_sockets {
            get_or_create_usc
        } else {
            create_new_usc
        };

        let usc = if self.bind_addresseses.is_empty() {
            if server_addr.is_ipv4() {
                (usc_creator)(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            } else {
                (usc_creator)(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
            }
        } else {
            // similar to std::net::UdpSocket::bind
            let mut last_error = None;

            let no_available_address =
                || io::Error::new(io::ErrorKind::AddrNotAvailable, "No available address");
            self.bind_addresseses
                .iter()
                .filter(|addr| addr.is_ipv4() == server_addr.is_ipv4())
                .find_map(|suite_addr| {
                    match (usc_creator)(suite_addr) {
                        Ok(usc) => return Some(usc),
                        Err(err) => last_error = Some(err),
                    }
                    None
                })
                .ok_or(last_error.unwrap_or_else(no_available_address))
        }?;

        let pathway = Pathway::Direct {
            local: usc.local_addr(),
            remote: server_addr,
        };

        // 创建initial_scid，不能重复
        // 倒不是与路由表中的重复，而是与全局的QuicConnection集合中的key重复
        // 有可能，连向同一个服务器的，四元组一样，连接id不一样而已？
        // 这是个问题，得解决下！
        let initial_scid = std::iter::repeat_with(Self::gen_cid)
            .find(|cid| !CONNECTIONS.contains_key(&ConnKey::Client(*cid)))
            .unwrap();

        let streams_ctrl = (self.streams_controller)(
            self.parameters.initial_max_streams_bidi().into_inner(),
            self.parameters.initial_max_streams_uni().into_inner(),
        );

        let token_registry = match &self.token_sink {
            Some(sink) => ArcTokenRegistry::with_sink(server_name.clone(), sink.clone()),
            None => ArcTokenRegistry::default_sink(server_name.clone()),
        };

        let tls_config = self.tls_config.clone();
        let key = ConnKey::Client(initial_scid);
        let inner = ArcConnection::new_client(
            initial_scid,
            server_name,
            self.parameters,
            streams_ctrl,
            tls_config,
            token_registry,
        );
        inner.add_initial_path(pathway, usc);

        CONNECTIONS.insert(key.clone(), inner.clone());
        let conn = QuicConnection { key, inner };

        Ok(Arc::new(conn))
    }
}

/// A builder for [`QuicClient`].
pub struct QuicClientBuilder<T> {
    bind_addresses: Vec<SocketAddr>,
    reuse_udp_sockets: bool,
    reuse_connection: bool,
    enable_happy_eyepballs: bool,
    prefer_versions: Vec<u32>,
    parameters: Parameters,
    tls_config: T,
    streams_controller: Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync>,
    token_sink: Option<Arc<dyn TokenSink>>,
}

impl<T> QuicClientBuilder<T> {
    /// Bind the client to the given addresses.
    ///
    /// If you call this multiple times, only the last `addrs` will be used.
    ///
    /// Although you dont bind any address, each time the client initiates a new connection, the client will use the
    /// address and port that dynamic assigned by the system.
    ///
    /// To know more about how the client selects the socket address, read [`QuicClient::connect`].
    pub fn bind(mut self, addrs: impl ToSocketAddrs) -> io::Result<Self> {
        self.bind_addresses.clear();
        self.bind_addresses.extend(addrs.to_socket_addrs()?);
        Ok(self)
    }

    /// (WIP)Enable efficiently reuse connections.
    ///
    /// If you enable this option, the client will try to reuse the connection that has already connected to the server,
    /// this means that the client will not initiates a new connection, but return the existing connection when you call
    /// [`QuicClient::connect`].
    pub fn reuse_connection(mut self) -> Self {
        self.reuse_connection = true;
        self
    }

    /// Enable reuse UDP sockets.
    ///
    /// By default, the client will not use the same address as other connections, which means that the client must bind
    /// to a new address every time it initiates a connection. If you enable this option, the client cloud share the same
    /// address with other connections. This option can only determine the behavior of this client when establishing a
    /// new connection.
    ///
    /// If you dont bind any address, this option will not take effect because the client will use the address and port
    /// that dynamic assigned by the system each time it initiates a new connection.
    pub fn reuse_udp_sockets(mut self) -> Self {
        self.reuse_udp_sockets = true;
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

    /// Specify the [transport parameters] for the client.
    ///
    /// If you call this multiple times, only the last `parameters` will be used.
    ///
    /// Usually, you don't need to call this method, because the client will use a set of default parameters.
    ///
    /// [transport parameters](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit)
    pub fn with_parameters(mut self, parameters: ClientParameters) -> Self {
        self.parameters = parameters.into();
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
            bind_addresses: self.bind_addresses,
            reuse_udp_sockets: self.reuse_udp_sockets,
            reuse_connection: self.reuse_connection,
            enable_happy_eyepballs: self.enable_happy_eyepballs,
            prefer_versions: self.prefer_versions,
            parameters: self.parameters,
            tls_config: self.tls_config.with_root_certificates(root_store),
            streams_controller: self.streams_controller,
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
            bind_addresses: self.bind_addresses,
            reuse_udp_sockets: self.reuse_udp_sockets,
            reuse_connection: self.reuse_connection,
            enable_happy_eyepballs: self.enable_happy_eyepballs,
            prefer_versions: self.prefer_versions,
            parameters: self.parameters,
            tls_config: self.tls_config.with_webpki_verifier(verifier),
            streams_controller: self.streams_controller,
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
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_addresses: self.bind_addresses,
            reuse_udp_sockets: self.reuse_udp_sockets,
            reuse_connection: self.reuse_connection,
            enable_happy_eyepballs: self.enable_happy_eyepballs,
            prefer_versions: self.prefer_versions,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_auth_cert(cert_chain, key_der)
                .expect("The private key was wrong encoded or failed validation"),
            streams_controller: self.streams_controller,
            token_sink: self.token_sink,
        }
    }

    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// This is a useful wapper of [`QuicClientBuilder::with_cert`], we do the *pem* file decoding and error handling
    /// for you.
    pub fn with_cert_files(
        self,
        cert_chain_file: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
    ) -> io::Result<QuicClientBuilder<TlsClientConfig>> {
        let (cert_chain, key_der) = util::parse_pem_files(cert_chain_file, key_file)?;
        Ok(self.with_cert(cert_chain, key_der))
    }

    /// Do not support client auth.
    pub fn without_cert(self) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_addresses: self.bind_addresses,
            reuse_udp_sockets: self.reuse_udp_sockets,
            reuse_connection: self.reuse_connection,
            enable_happy_eyepballs: self.enable_happy_eyepballs,
            prefer_versions: self.prefer_versions,
            parameters: self.parameters,
            tls_config: self.tls_config.with_no_client_auth(),
            streams_controller: self.streams_controller,
            token_sink: self.token_sink,
        }
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_cert_resolver(
        self,
        cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_addresses: self.bind_addresses,
            reuse_udp_sockets: self.reuse_udp_sockets,
            reuse_connection: self.reuse_connection,
            enable_happy_eyepballs: self.enable_happy_eyepballs,
            prefer_versions: self.prefer_versions,
            parameters: self.parameters,
            tls_config: self.tls_config.with_client_cert_resolver(cert_resolver),
            streams_controller: self.streams_controller,
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
        QuicClient {
            bind_addresseses: self.bind_addresses,
            reuse_udp_sockets: self.reuse_udp_sockets,
            _reuse_connection: self.reuse_connection,
            _enable_happy_eyepballs: self.enable_happy_eyepballs,
            _prefer_versions: self.prefer_versions,
            parameters: self.parameters,
            tls_config: Arc::new(self.tls_config),
            streams_controller: self.streams_controller,
            token_sink: self.token_sink,
        }
    }
}
