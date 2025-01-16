use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use dashmap::DashSet;
use handy::Usc;
pub use qconnection::{builder::*, prelude::*};
use rustls::{
    client::{ResolvesClientCert, WantsClientCert},
    ClientConfig as TlsClientConfig, ConfigBuilder, WantsVerifier,
};
use tokio::sync::mpsc;

use crate::{
    util::{ToCertificate, ToPrivateKey},
    PROTO,
};

type TlsClientConfigBuilder<T> = ConfigBuilder<TlsClientConfig, T>;

/// A quic client that can initiates connections to servers.
pub struct QuicClient {
    bind_addresseses: Vec<SocketAddr>,
    active_addresses: Arc<DashSet<SocketAddr>>,
    reuse_udp_sockets: bool,
    _reuse_connection: bool, // TODO
    // TODO: 好像得创建2个quic连接，一个用ipv4，一个用ipv6
    //       然后看谁先收到服务器的响应比较好
    _enable_happy_eyepballs: bool,
    _prefer_versions: Vec<u32>,
    _defer_idle_timeout: Duration,
    parameters: ClientParameters,
    // TODO: 要改成一个加载上次连接的parameters的函数，根据server name
    _remembered: Option<CommonParameters>,
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
            bind_addresses: vec![],
            reuse_udp_sockets: false,
            reuse_connection: true,
            enable_happy_eyepballs: false,
            prefer_versions: vec![1],
            defer_idle_timeout: Duration::ZERO,
            parameters: ClientParameters::default(),
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
            defer_idle_timeout: Duration::ZERO,
            parameters: ClientParameters::default(),
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
            defer_idle_timeout: Duration::ZERO,
            parameters: ClientParameters::default(),
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
    ) -> io::Result<Arc<Connection>> {
        let server_name = server_name.into();

        let local_addr = if self.bind_addresseses.is_empty() {
            let usc = if server_addr.is_ipv4() {
                Usc::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            } else {
                Usc::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
            }?;
            let local_addr = usc.local_addr()?;
            let active_address = self.active_addresses.clone();
            tokio::spawn(async move {
                match PROTO.listen_on(local_addr, Arc::new(usc)).unwrap().await {
                    Err(_) => active_address.remove(&local_addr),
                };
            });
            self.active_addresses.insert(local_addr);
            local_addr
        } else {
            // similar to std::net::UdpSocket::bind
            let mut last_error = None;

            let no_available_address =
                || io::Error::new(io::ErrorKind::AddrNotAvailable, "No available address");
            self.bind_addresseses
                .iter()
                .filter(|addr| addr.is_ipv4() == server_addr.is_ipv4())
                .find_map(|&local_addr| {
                    if self.active_addresses.contains(&local_addr) {
                        if self.reuse_udp_sockets {
                            Some(local_addr)
                        } else {
                            None
                        }
                    } else {
                        let usc = match Usc::bind(local_addr) {
                            Ok(usc) => usc,
                            Err(error) => {
                                last_error = Some(error);
                                return None;
                            }
                        };
                        let local_addr = match usc.local_addr() {
                            Ok(local_addr) => local_addr,
                            Err(error) => {
                                last_error = Some(error);
                                return None;
                            }
                        };
                        let active_address = self.active_addresses.clone();
                        tokio::spawn(async move {
                            match PROTO.listen_on(local_addr, Arc::new(usc)).unwrap().await {
                                Err(_) => active_address.remove(&local_addr),
                            };
                        });
                        Some(local_addr)
                    }
                })
                .ok_or(last_error.unwrap_or_else(no_available_address))?
        };

        let pathway = Pathway::new(
            Endpoint::Direct { addr: local_addr },
            Endpoint::Direct { addr: server_addr },
        );

        let token_sink = self
            .token_sink
            .clone()
            .unwrap_or_else(|| Arc::new(NoopTokenRegistry));

        let (event_broker, mut events) = mpsc::unbounded_channel();

        let connection = Arc::new(
            Connection::with_token_sink(server_name, token_sink)
                .with_parameters(self.parameters, None)
                .with_tls_config(self.tls_config.clone())
                .with_streams_ctrl(&self.streams_controller)
                .with_interface(PROTO.clone(), ConnectionId::random_gen(8))
                .run_with(event_broker),
        );

        connection.add_path(pathway)?;

        tokio::spawn({
            let connection = connection.clone();
            async move {
                while let Some(event) = events.recv().await {
                    match event {
                        Event::Handshaked => {}
                        Event::Failed(error) => connection.enter_closing(error.into()),
                        Event::Closed(ccf) => connection.enter_draining(ccf),
                        Event::StatelessReset => {}
                        Event::Terminated => { /* Todo: connections set */ }
                    }
                }
            }
        });

        Ok(connection)
    }
}

/// A builder for [`QuicClient`].
pub struct QuicClientBuilder<T> {
    bind_addresses: Vec<SocketAddr>,
    reuse_udp_sockets: bool,
    reuse_connection: bool,
    enable_happy_eyepballs: bool,
    prefer_versions: Vec<u32>,
    defer_idle_timeout: Duration,
    parameters: ClientParameters,
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

    /// Provide an option to defer an idle timeout.
    ///
    /// This facility could be used when the application wishes to avoid losing
    /// state that has been associated with an open connection but does not expect
    /// to exchange application data for some time.
    ///
    /// See [Deferring Idle Timeout](https://datatracker.ietf.org/doc/html/rfc9000#name-deferring-idle-timeout)
    /// of [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)
    /// for more information.
    pub fn keep_alive(mut self, duration: Duration) -> Self {
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
            defer_idle_timeout: self.defer_idle_timeout,
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
            defer_idle_timeout: self.defer_idle_timeout,
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
        cert_chain: impl ToCertificate,
        key_der: impl ToPrivateKey,
    ) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_addresses: self.bind_addresses,
            reuse_udp_sockets: self.reuse_udp_sockets,
            reuse_connection: self.reuse_connection,
            enable_happy_eyepballs: self.enable_happy_eyepballs,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_auth_cert(cert_chain.to_certificate(), key_der.to_private_key())
                .expect("The private key was wrong encoded or failed validation"),
            streams_controller: self.streams_controller,
            token_sink: self.token_sink,
        }
    }

    /// Do not support client auth.
    pub fn without_cert(self) -> QuicClientBuilder<TlsClientConfig> {
        QuicClientBuilder {
            bind_addresses: self.bind_addresses,
            reuse_udp_sockets: self.reuse_udp_sockets,
            reuse_connection: self.reuse_connection,
            enable_happy_eyepballs: self.enable_happy_eyepballs,
            prefer_versions: self.prefer_versions,
            defer_idle_timeout: self.defer_idle_timeout,
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
            defer_idle_timeout: self.defer_idle_timeout,
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
            active_addresses: Default::default(),
            reuse_udp_sockets: self.reuse_udp_sockets,
            _reuse_connection: self.reuse_connection,
            _enable_happy_eyepballs: self.enable_happy_eyepballs,
            _prefer_versions: self.prefer_versions,
            _defer_idle_timeout: self.defer_idle_timeout,
            parameters: self.parameters,
            // TODO: 要能加载上次连接的parameters
            _remembered: None,
            tls_config: Arc::new(self.tls_config),
            streams_controller: self.streams_controller,
            token_sink: self.token_sink,
        }
    }
}
