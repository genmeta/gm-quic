use std::{
    io::{self},
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, LazyLock, RwLock, Weak},
};

use dashmap::DashMap;
use qbase::{
    cid::ConnectionId,
    packet::{
        header::{GetDcid, GetScid},
        long, DataHeader, DataPacket, InitialHeader, RetryHeader,
    },
    param::{Parameters, ServerParameters},
    sid::{handy::ConsistentConcurrency, ControlConcurrency},
    token::{ArcTokenRegistry, TokenProvider},
    util::ArcAsyncDeque,
};
use qconnection::{conn::ArcConnection, path::Pathway, router::Router, usc::ArcUsc};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    server::{danger::ClientCertVerifier, NoClientAuth, ResolvesServerCert, WantsServerCert},
    ConfigBuilder, ServerConfig as TlsServerConfig, WantsVerifier,
};

use crate::{get_or_create_usc, ConnKey, QuicConnection, CONNECTIONS};

type TlsServerConfigBuilder<T> = ConfigBuilder<TlsServerConfig, T>;
type QuicListner = ArcAsyncDeque<(Arc<QuicConnection>, Pathway)>;

/// 理应全局只有一个server
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
    sockets: DashMap<SocketAddr, ArcUsc>,
    listener: QuicListner,
    passive_listening: bool,
    _supported_versions: Vec<u32>,
    _load_balance: Arc<dyn Fn(InitialHeader) -> Option<RetryHeader> + Send + Sync + 'static>,
    parameters: Parameters,
    tls_config: Arc<TlsServerConfig>,
    streams_controller:
        Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync + 'static>,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

impl QuicServer {
    /// Start to build a QuicServer.
    pub fn buidler() -> QuicServerBuilder<TlsServerConfigBuilder<WantsVerifier>> {
        QuicServerBuilder {
            passive_listening: false,
            supported_versions: Vec::with_capacity(2),
            load_balance: Arc::new(|_| None),
            parameters: Parameters::default(),
            tls_config: TlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]),
            streams_controller: Box::new(|bi, uni| Box::new(ConsistentConcurrency::new(bi, uni))),
            token_provider: None,
        }
    }

    /// Start to build a QuicServer with the given TLS configuration.
    ///
    /// This is useful when you want to customize the TLS configuration, or integrate qm-quic with other crates.
    pub fn builder_with_tls(tls_config: TlsServerConfig) -> QuicServerBuilder<TlsServerConfig> {
        QuicServerBuilder {
            passive_listening: false,
            supported_versions: Vec::with_capacity(2),
            load_balance: Arc::new(|_| None),
            parameters: Parameters::default(),
            tls_config,
            streams_controller: Box::new(|bi, uni| Box::new(ConsistentConcurrency::new(bi, uni))),
            token_provider: None,
        }
    }

    /// Start to build a QuicServer with the given tls crypto provider.
    pub fn builder_with_crypto_provieder(
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> QuicServerBuilder<TlsServerConfigBuilder<WantsVerifier>> {
        QuicServerBuilder {
            passive_listening: false,
            supported_versions: Vec::with_capacity(2),
            load_balance: Arc::new(|_| None),
            parameters: Parameters::default(),
            tls_config: TlsServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap(),
            streams_controller: Box::new(|bi, uni| Box::new(ConsistentConcurrency::new(bi, uni))),
            token_provider: None,
        }
    }

    /// Get the addresses that the server still listens to.
    ///
    /// The return vector may be different from the addresses you passed to the [`QuicServerBuilder::listen`] method,
    /// because the server may fail to bind to some addresses. And, while the server is running, some sockets may be
    /// closed unexpectedly.
    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.sockets.iter().map(|entry| *entry.key()).collect()
    }

    /// Accept the next incoming connection.
    ///
    /// The connection accepted may still in the progress of handshake, but you can use it to do anything you want, such
    /// as sending data, receiving data... operations will be pending until the connection is connected or closed.
    ///
    /// If all listening udp sockets are closed, this method will return an error.
    pub async fn accept(&self) -> io::Result<(Arc<QuicConnection>, Pathway)> {
        // TODO: 错误
        let error = || {
            // let msg = "All listening udp sockets are closed";
            // io::Error::new(io::ErrorKind::AddrNotAvailable, msg)
            unreachable!()
        };
        // 这个VecDeque永远不会被close，所以这里不会是None
        self.listener.pop().await.ok_or_else(error)
    }
}

// internal methods
impl QuicServer {
    pub(crate) fn try_to_accept_conn_from(mut packet: DataPacket, pathway: Pathway, usc: &ArcUsc) {
        let Some(server) = SERVER.read().unwrap().upgrade() else {
            return;
        };

        // 剔除来自没被监听的地址的包
        if !(server.passive_listening || server.sockets.contains_key(&pathway.local_addr())) {
            return;
        }

        let initial_scid =
            std::iter::repeat_with(|| ConnectionId::random_gen_with_mark(8, 0, 0x7F))
                .find(|cid| !CONNECTIONS.contains_key(&ConnKey::Server(*cid)))
                .unwrap();
        let (initial_dcid, client_initial_dcid) = match &mut packet.header {
            DataHeader::Long(long::DataHeader::Initial(hdr)) => {
                let client_dcid = *hdr.get_dcid();
                hdr.dcid = initial_scid;
                (*hdr.get_scid(), client_dcid)
            }
            DataHeader::Long(long::DataHeader::ZeroRtt(hdr)) => {
                let client_dcid = *hdr.get_dcid();
                hdr.dcid = initial_scid;
                (*hdr.get_scid(), client_dcid)
            }
            _ => return,
        };

        let streams_ctrl = (server.streams_controller)(
            server.parameters.initial_max_streams_bidi().into_inner(),
            server.parameters.initial_max_streams_uni().into_inner(),
        );

        let token_registry = match &server.token_provider {
            Some(provider) => ArcTokenRegistry::with_provider(provider.clone()),
            None => ArcTokenRegistry::default_provider(),
        };

        let initial_keys = server.initial_server_keys(client_initial_dcid);
        let tls_config = server.tls_config.clone();
        let inner = ArcConnection::new_server(
            initial_scid,
            initial_dcid,
            initial_keys,
            server.parameters,
            streams_ctrl,
            tls_config,
            token_registry,
        );
        inner.add_initial_path(pathway, usc.clone());
        let conn = QuicConnection {
            key: ConnKey::Server(initial_scid),
            inner: inner.clone(), // emm...
        };
        log::info!("incoming connection established");
        server.listener.push_back((Arc::new(conn), pathway.filp()));
        CONNECTIONS.insert(ConnKey::Server(initial_scid), inner);
        _ = Router::try_to_route_packet_from(packet, pathway, usc);
    }

    pub(crate) fn on_socket_close(addr: SocketAddr) {
        if let Some(server) = SERVER.read().unwrap().upgrade() {
            let bind_address_removed = server.sockets.remove(&addr).is_some();
            // 所有已经绑定的地址都被关闭了，并且被动监听没有开启，那么就关闭server的监听...
            // THINK: 不可能再接收新连接的情况下，Listener应该被立刻关闭？否
            // if bind_address_removed && !server.passive_listening && server.sockets.is_empty() {
            //     server.listener.close();
            // }
            _ = bind_address_removed;
        }
    }

    fn initial_server_keys(&self, dcid: ConnectionId) -> rustls::quic::Keys {
        let suite = self
            .tls_config
            .crypto_provider()
            .cipher_suites
            .iter()
            .find_map(|cs| match (cs.suite(), cs.tls13()) {
                (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => suite.quic_suite(),
                _ => None,
            })
            .unwrap();
        suite.keys(&dcid, rustls::Side::Server, rustls::quic::Version::V1)
    }

    /// Set the server as the global server.
    fn listen(self: &Arc<Self>) -> io::Result<()> {
        // 全局Server是Weak，用户持有的Arc Server全都被Drop后，全局Server自然会变成空
        let mut server = SERVER.write().unwrap();
        if server.strong_count() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "There is already a server running",
            ));
        }
        *server = Arc::downgrade(self);
        Ok(())
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
    passive_listening: bool,
    load_balance: Arc<dyn Fn(InitialHeader) -> Option<RetryHeader> + Send + Sync + 'static>,
    parameters: Parameters,
    tls_config: T,
    streams_controller:
        Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync + 'static>,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

/// The builder for the quic server with SNI enabled.
pub struct QuicServerSniBuilder<T> {
    supported_versions: Vec<u32>,
    passive_listening: bool,
    load_balance: Arc<dyn Fn(InitialHeader) -> Option<RetryHeader> + Send + Sync + 'static>,
    hosts: Arc<DashMap<String, Host>>,
    parameters: Parameters,
    tls_config: T,
    streams_controller:
        Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync + 'static>,
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

    /// (WIP)Specify the strategy for sending retry packets.
    ///
    /// If you call this multiple times, only the last `load_balance` will be used.
    ///
    /// The `load_balance` will be called when the server receives an [Initial packet]. If `load_balance` returns [`Some`],
    /// the server will send a [Retry packet] to the client. Otherwise, the server will continue the handshake with the
    /// client, and you can get the incoming connection by calling the [`QuicServer::accept`] method.
    ///
    /// [Initial packet](https://www.rfc-editor.org/rfc/rfc9000.html#name-initial-packet)
    /// [Retry packet](https://www.rfc-editor.org/rfc/rfc9000.html#name-retry-packet)
    pub fn with_load_balance(
        mut self,
        load_balance: Arc<dyn Fn(InitialHeader) -> Option<RetryHeader> + Send + Sync + 'static>,
    ) -> Self {
        self.load_balance = load_balance;
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

    /// Specify the [transport parameters] for the server.
    ///
    /// If you call this multiple times, only the last `parameters` will be used.
    ///
    /// Usually, you don't need to call this method, because the server will use a set of default parameters.
    ///
    /// [transport parameters](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit)
    pub fn with_parameters(mut self, parameters: ServerParameters) -> Self {
        self.parameters = parameters.into();
        self
    }

    /// Accept connections from addresses that are not listened to.
    ///
    /// Passive listening is that the server will accept all connections from all bound address, not only the given
    /// listening addresses.
    ///
    /// For example, you started a client and connected to a remote server. If the passive listening is enabled, the
    /// server will accept the connections that connected to the addresses that client used. This is useful in some
    /// cases, such as the server is behind a NAT.
    pub fn enable_passive_listening(mut self) -> Self {
        self.passive_listening = true;
        self
    }
}

impl QuicServerBuilder<TlsServerConfigBuilder<WantsVerifier>> {
    /// Choose how to verify client certificates.
    pub fn with_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn ClientCertVerifier>,
    ) -> QuicServerBuilder<TlsServerConfigBuilder<WantsServerCert>> {
        QuicServerBuilder {
            passive_listening: self.passive_listening,
            supported_versions: self.supported_versions,
            load_balance: self.load_balance,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_cert_verifier(client_cert_verifier),
            streams_controller: self.streams_controller,
            token_provider: self.token_provider,
        }
    }

    /// Disable client authentication.
    pub fn without_cert_verifier(
        self,
    ) -> QuicServerBuilder<TlsServerConfigBuilder<WantsServerCert>> {
        QuicServerBuilder {
            passive_listening: self.passive_listening,
            supported_versions: self.supported_versions,
            load_balance: self.load_balance,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_cert_verifier(Arc::new(NoClientAuth)),
            streams_controller: self.streams_controller,
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
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> QuicServerBuilder<TlsServerConfig> {
        QuicServerBuilder {
            passive_listening: self.passive_listening,
            supported_versions: self.supported_versions,
            load_balance: self.load_balance,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_single_cert(cert_chain, key_der)
                .expect("The private key was wrong encoded or failed validation"),
            streams_controller: self.streams_controller,
            token_provider: self.token_provider,
        }
    }

    /// Add a host with a certificate chain and a private key from cert files.
    ///
    /// This is a useful wapper of [`QuicServerBuilder::with_single_cert_files`], we do the file decoding(by using
    /// [`PemObject`] trait) and error handling for you.
    pub fn with_single_cert_files(
        self,
        cert_chain_file: impl AsRef<std::path::Path>,
        key_file: impl AsRef<std::path::Path>,
    ) -> io::Result<QuicServerBuilder<TlsServerConfig>> {
        let cast_pem_error = |e| match e {
            rustls::pki_types::pem::Error::Io(error) => error,
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        };
        let cert_chain = CertificateDer::pem_file_iter(cert_chain_file)
            .map_err(cast_pem_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(cast_pem_error)?;
        let key_der = PrivateKeyDer::from_pem_file(key_file).map_err(cast_pem_error)?;
        Ok(self.with_single_cert(cert_chain, key_der))
    }

    /// Sets a single certificate chain, matching private key and optional OCSP
    /// response.  This certificate and key is used for all
    /// subsequent connections, irrespective of things like SNI hostname.
    ///
    /// Read [`TlsServerConfigBuilder::with_single_cert_with_ocsp`] for more.
    pub fn with_single_cert_with_ocsp(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
        ocsp: Vec<u8>,
    ) -> QuicServerBuilder<TlsServerConfig> {
        QuicServerBuilder {
            passive_listening: self.passive_listening,
            supported_versions: self.supported_versions,
            load_balance: self.load_balance,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_single_cert_with_ocsp(cert_chain, key_der, ocsp)
                .expect("The private key was wrong encoded or failed validation"),
            streams_controller: self.streams_controller,
            token_provider: self.token_provider,
        }
    }

    /// Add a host with a certificate chain and a private key from cert files.
    ///
    /// This is a useful wapper of [`QuicServerBuilder::with_single_cert_files_with_ocsp`], we do the file decoding(by
    /// using [`PemObject`] trait) and error handling for you.
    pub fn with_single_cert_files_with_ocsp(
        self,
        cert_chain_file: impl AsRef<std::path::Path>,
        key_file: impl AsRef<std::path::Path>,
        ocsp: Vec<u8>,
    ) -> io::Result<QuicServerBuilder<TlsServerConfig>> {
        let cast_pem_error = |e| match e {
            rustls::pki_types::pem::Error::Io(error) => error,
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        };
        let cert_chain = CertificateDer::pem_file_iter(cert_chain_file)
            .map_err(cast_pem_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(cast_pem_error)?;
        let key_der = PrivateKeyDer::from_pem_file(key_file).map_err(cast_pem_error)?;
        Ok(QuicServerBuilder {
            passive_listening: self.passive_listening,
            supported_versions: self.supported_versions,
            load_balance: self.load_balance,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_single_cert_with_ocsp(cert_chain, key_der, ocsp)
                .expect("The private key was wrong encoded or failed validation"),
            streams_controller: self.streams_controller,
            token_provider: self.token_provider,
        })
    }

    /// Enable TLS SNI (Server Name Indication) extensions.
    pub fn enable_sni(self) -> QuicServerSniBuilder<TlsServerConfig> {
        let hosts = Arc::new(DashMap::new());
        QuicServerSniBuilder {
            passive_listening: self.passive_listening,
            supported_versions: self.supported_versions,
            load_balance: self.load_balance,
            parameters: Default::default(),
            tls_config: self
                .tls_config
                .with_cert_resolver(Arc::new(VirtualHosts(hosts.clone()))),
            hosts,
            streams_controller: self.streams_controller,
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
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Self {
        let private_key = self
            .tls_config
            .crypto_provider()
            .key_provider
            .load_private_key(key_der)
            .unwrap();

        let server_name = server_name.into();
        self.hosts.insert(
            server_name,
            Host {
                cert_chain,
                private_key,
            },
        );
        self
    }

    /// Add a host with a certificate chain and a private key decoded from cert files.
    ///
    /// This is a useful wapper of [`QuicServerSniBuilder::add_host`], we do the file decoding(by using [`PemObject`]
    /// trait) and error handling for you.
    pub fn add_host_with_cert_files(
        self,
        server_name: impl Into<String>,
        cert_chain_file: impl AsRef<std::path::Path>,
        key_file: impl AsRef<std::path::Path>,
    ) -> io::Result<Self> {
        let cast_pem_error = |e| match e {
            rustls::pki_types::pem::Error::Io(error) => error,
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        };
        let cert_chain = CertificateDer::pem_file_iter(cert_chain_file)
            .map_err(cast_pem_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(cast_pem_error)?;
        let key_der = PrivateKeyDer::from_pem_file(key_file).map_err(cast_pem_error)?;
        Ok(self.add_host(server_name, cert_chain, key_der))
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
    pub fn with_alpns(mut self, alpn: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.tls_config.alpn_protocols.extend(alpn);
        self
    }

    /// Start to listen for incoming connections.
    ///
    /// Once listen is called, the server will start to accept incoming connections, do the handshake automatically, and
    /// you can get the incoming connection by calling the [`QuicServer::accept`] method.
    ///
    /// Note that there can be only one server running at the same time, so this method will return an error if there is
    /// already a server running.
    ///
    /// When the `QuicServer` is dropped, the server will stop listening for incoming connections, and you can start a
    /// new server by calling the [`QuicServerBuilder::listen`] method again.
    ///
    /// ## If the passive listening is not enabled
    ///
    /// This method will try to bind all of the given addresses. The server will *only* accept connections from the given
    /// addresses that successfully bound.
    ///
    /// If all given addresses are failed to bind, this method will return an error.
    ///
    /// ## If the passive listening is enabled
    ///
    /// This method will also attempt to bind to the given address, but the server will accept connections from *all*
    /// addresses that gm-quic has already bound to, such as those used by other local clients to connect to the remote
    /// server.
    ///
    /// Although all given addresses are failed to bind, the server can still accept connections from other addresses.
    pub fn listen(self, addresses: impl ToSocketAddrs) -> io::Result<Arc<QuicServer>> {
        let uscs = addresses
            .to_socket_addrs()?
            .filter_map(|address| {
                let arc_usc = get_or_create_usc(&address).map_err(|e| log::error!("{e}"));
                Some((address, arc_usc.ok()?))
            })
            .collect::<DashMap<_, _>>();
        if uscs.is_empty() && !self.passive_listening {
            let error = "all addresses are not available";
            let error = io::Error::new(io::ErrorKind::AddrNotAvailable, error);
            return Err(error);
        }

        let quic_server = Arc::new(QuicServer {
            sockets: uscs,
            passive_listening: self.passive_listening,
            listener: Default::default(),
            _supported_versions: self.supported_versions,
            _load_balance: self.load_balance,
            parameters: self.parameters,
            tls_config: Arc::new(self.tls_config),
            streams_controller: self.streams_controller,
            token_provider: self.token_provider,
        });
        quic_server.listen()?;
        Ok(quic_server)
    }
}

impl QuicServerSniBuilder<TlsServerConfig> {
    /// Specify the `alpn_protocol` that the server supports.
    ///
    /// If you call this multiple times, all the `alpn_protocol` will be used.
    ///
    /// If you never call this method, we will not do ALPN negotiation with the client.
    pub fn with_alpns(mut self, alpn: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.tls_config.alpn_protocols.extend(alpn);
        self
    }

    /// Start to listen for incoming connections.
    ///
    /// Once listen is called, the server will start to accept incoming connections, do the handshake automatically, and
    /// you can get the incoming connection by calling the [`QuicServer::accept`] method.
    ///
    /// Note that there can be only one server running at the same time, so this method will return an error if there is
    /// already a server running.
    ///
    /// When the `QuicServer` is dropped, the server will stop listening for incoming connections, and you can start a
    /// new server by calling the [`QuicServerBuilder::listen`] method again.
    ///
    /// ## If the passive listening is not enabled
    ///
    /// This method will try to bind all of the given addresses. The server will *only* accept connections from the given
    /// addresses that successfully bound.
    ///
    /// If all given addresses are failed to bind, this method will return an error.
    ///
    /// ## If the passive listening is enabled
    ///
    /// This method will also attempt to bind to the given address, but the server will accept connections from *all*
    /// addresses that gm-quic has already bound to, such as those used by other local clients to connect to the remote
    /// server.
    ///
    /// Although all given addresses are failed to bind, the server can still accept connections from other addresses.
    pub fn listen(self, addresses: impl ToSocketAddrs) -> io::Result<Arc<QuicServer>> {
        let uscs = addresses
            .to_socket_addrs()?
            .filter_map(|address| {
                let arc_usc = get_or_create_usc(&address).map_err(|e| log::error!("{e}"));
                Some((address, arc_usc.ok()?))
            })
            .collect::<DashMap<_, _>>();
        if uscs.is_empty() && !self.passive_listening {
            let error = "all addresses are not available";
            let error = io::Error::new(io::ErrorKind::AddrNotAvailable, error);
            return Err(error);
        }
        let quic_server = Arc::new(QuicServer {
            sockets: uscs,
            passive_listening: self.passive_listening,
            listener: Default::default(),
            _supported_versions: self.supported_versions,
            _load_balance: self.load_balance,
            parameters: self.parameters,
            tls_config: Arc::new(self.tls_config),
            streams_controller: self.streams_controller,
            token_provider: self.token_provider,
        });
        quic_server.listen()?;
        Ok(quic_server)
    }
}
