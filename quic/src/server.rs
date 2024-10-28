use std::{
    collections::HashMap,
    io::{self},
    iter::FusedIterator,
    net::SocketAddr,
    path::Path,
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
use qconnection::{connection::ArcConnection, path::Pathway, router::Router, usc::ArcUsc};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{danger::ClientCertVerifier, NoClientAuth, ResolvesServerCert, WantsServerCert},
    ConfigBuilder, ServerConfig as TlsServerConfig, WantsVerifier,
};

use crate::{get_or_create_usc, ConnKey, QuicConnection, CONNECTIONS};

type TlsServerConfigBuilder<T> = ConfigBuilder<TlsServerConfig, T>;
type QuicListner = ArcAsyncDeque<(QuicConnection, SocketAddr)>;

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

/// 服务端的Quic连接，可以接受新的连接
/// 实际上服务端的性质，类似于收包。不管包从哪个usc来，都可以根据需要来创建
/// 要想有服务端的功能，得至少有一个usc可以收包。
/// 如果不创建QuicServer，那意味着不接收新连接
pub struct QuicServer {
    uscs: HashMap<SocketAddr, ArcUsc>,
    listener: QuicListner,
    _restrict: bool,
    _supported_versions: Vec<u32>,
    _load_balance: Arc<dyn Fn(InitialHeader) -> Option<RetryHeader> + Send + Sync + 'static>,
    parameters: Parameters,
    tls_config: Arc<TlsServerConfig>,
    streams_controller:
        Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync + 'static>,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

#[derive(Clone)]
pub struct ArcQuicServer(Arc<QuicServer>);

impl ArcQuicServer {
    /// 指定绑定的地址，即服务端的usc的监听地址
    /// 监听地址可以有多个，但必须都得是本地能绑定成功的，否则会panic
    /// 监听地址若为空，则会默认创建一个
    /// 严格模式是指，只有在这些地址上收到并创建的新连接，才会被接受
    pub fn bind(
        addresses: impl IntoIterator<Item = SocketAddr>,
        restrict: bool,
    ) -> QuicServerBuilder<TlsServerConfigBuilder<WantsVerifier>> {
        QuicServerBuilder {
            addresses: addresses.into_iter().collect(),
            restrict,
            supported_versions: Vec::with_capacity(2),
            load_balance: Arc::new(|_| None),
            parameters: Parameters::default(),
            tls_config: TlsServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap(),
            streams_controller: Box::new(|bi, uni| Box::new(ConsistentConcurrency::new(bi, uni))),
            token_provider: None,
        }
    }

    pub fn addresses(&self) -> impl ExactSizeIterator<Item = &SocketAddr> + FusedIterator {
        self.0.uscs.keys()
    }

    /// 监听新连接的到来
    /// 新连接可能通过本地的任何一个有效usc来创建
    /// 只有调用该函数，才会有被动创建的Connection存放队列，等待着应用层来处理
    pub async fn accept(&self) -> io::Result<(QuicConnection, SocketAddr)> {
        let listening_stopped = || io::Error::new(io::ErrorKind::Other, "listening stopped");
        self.0.listener.pop().await.ok_or_else(listening_stopped)
    }

    pub(crate) fn try_to_accept_conn_from(mut packet: DataPacket, pathway: Pathway, usc: &ArcUsc) {
        let server = SERVER.read().unwrap();
        let Some(server) = server.upgrade() else {
            return;
        };
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

        let token_provider = match &server.token_provider {
            Some(provider) => ArcTokenRegistry::with_provider(provider.clone()),
            None => ArcTokenRegistry::default_provider(),
        };

        let initial_keys = server.initial_server_keys(client_initial_dcid);
        let inner = ArcConnection::new_server(
            initial_scid,
            initial_dcid,
            initial_keys,
            server.parameters,
            streams_ctrl,
            server.tls_config.clone(),
            token_provider,
        );
        inner.add_initial_path(pathway, usc.clone());
        let conn = QuicConnection {
            _key: ConnKey::Server(initial_scid),
            inner,
        };
        log::info!("incoming connection established");
        server
            .listener
            .push_back((conn.clone(), pathway.remote_addr()));
        CONNECTIONS.insert(ConnKey::Server(initial_scid), conn);
        _ = Router::try_to_route_packet_from(packet, pathway, usc);
    }
}

impl QuicServer {
    /// 获取所有监听的地址，因为客户端创建的每一个usc都可以成为监听端口
    pub fn initial_server_keys(&self, dcid: ConnectionId) -> rustls::quic::Keys {
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
}

#[derive(Debug)]
struct Host {
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: Arc<dyn rustls::sign::SigningKey>,
}

pub struct QuicServerBuilder<T> {
    addresses: Vec<SocketAddr>,
    restrict: bool,
    supported_versions: Vec<u32>,
    load_balance: Arc<dyn Fn(InitialHeader) -> Option<RetryHeader> + Send + Sync + 'static>,
    parameters: Parameters,
    tls_config: T,
    streams_controller:
        Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync + 'static>,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

pub struct QuicServerSniBuilder<T> {
    addresses: Vec<SocketAddr>,
    restrict: bool,
    supported_versions: Vec<u32>,
    load_balance: Arc<dyn Fn(InitialHeader) -> Option<RetryHeader> + Send + Sync + 'static>,
    hosts: Arc<DashMap<String, Host>>,
    parameters: Parameters,
    tls_config: T,
    streams_controller:
        Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync + 'static>,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

impl<T> QuicServerBuilder<T> {
    pub fn with_supported_versions(mut self, versions: impl IntoIterator<Item = u32>) -> Self {
        self.supported_versions.clear();
        self.supported_versions.extend(versions);
        self
    }

    /// 设置负载均衡器，当收到新连接的时候，是否需要为了负载均衡重定向到其他服务器
    /// 所谓负载均衡，就是收到新连接的Initial包，是否需要回复一个Retry，让客户端连接到新地址上
    pub fn with_load_balance(
        mut self,
        load_balance: Arc<dyn Fn(InitialHeader) -> Option<RetryHeader> + Send + Sync + 'static>,
    ) -> Self {
        self.load_balance = load_balance;
        self
    }

    /// TokenProvider有2个功能：
    /// TokenProvider需要向客户端颁发新Token
    /// 同时，收到新连接，TokenProvider也要验证客户端的Initial包中的Token
    pub fn with_token_provider(mut self, token_provider: Arc<dyn TokenProvider>) -> Self {
        self.token_provider = Some(token_provider);
        self
    }

    /// 设值服务端连接参数。若不设置，则会使用一组默认参数。
    /// 后续接受新的连接，会直接使用这些参数。不过在sni模式下，各个host可以有不同的参数，该函数将失去意义。
    /// 因此，它最好配合[`with_single_cert`]或者[`with_single_cert_with_ocsp`]一起使用
    /// 可以多次调用该函数，会覆盖上一次设置的参数。
    ///
    /// [`with_single_cert`]: QuicServerBuilder::with_single_cert
    /// [`with_single_cert_with_ocsp`]: QuicServerBuilder::with_single_cert_with_ocsp
    pub fn with_parameters(mut self, parameters: ServerParameters) -> Self {
        self.parameters = parameters.into();
        self
    }

    pub fn with_tls_config(
        self,
        tls_config: TlsServerConfig,
    ) -> QuicServerBuilder<TlsServerConfig> {
        QuicServerBuilder {
            addresses: self.addresses,
            restrict: self.restrict,
            supported_versions: self.supported_versions,
            load_balance: self.load_balance,
            parameters: self.parameters,
            tls_config,
            streams_controller: self.streams_controller,
            token_provider: self.token_provider,
        }
    }
}

impl QuicServerBuilder<TlsServerConfigBuilder<WantsVerifier>> {
    /// Choose how to verify client certificates.
    pub fn with_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn ClientCertVerifier>,
    ) -> QuicServerBuilder<TlsServerConfigBuilder<WantsServerCert>> {
        QuicServerBuilder {
            addresses: self.addresses,
            restrict: self.restrict,
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
            addresses: self.addresses,
            restrict: self.restrict,
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
    /// 所有的Host都符合泛域名证书的话，可以用该函数
    pub fn with_single_cert(
        self,
        cert_file: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
    ) -> QuicServerBuilder<TlsServerConfig> {
        let cert = std::fs::read(cert_file).unwrap();
        let cert_chain = vec![CertificateDer::from(cert)];

        let key = std::fs::read(key_file).unwrap();
        let key_der = PrivateKeyDer::try_from(key).unwrap();

        QuicServerBuilder {
            addresses: self.addresses,
            restrict: self.restrict,
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

    pub fn with_single_cert_with_ocsp(
        self,
        cert_file: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
        ocsp: Vec<u8>,
    ) -> QuicServerBuilder<TlsServerConfig> {
        let cert = std::fs::read(cert_file).unwrap();
        let cert_chain = vec![CertificateDer::from(cert)];

        let key = std::fs::read(key_file).unwrap();
        let key_der = PrivateKeyDer::try_from(key).unwrap();

        QuicServerBuilder {
            addresses: self.addresses,
            restrict: self.restrict,
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

    /// 应该是自动调用它，根据ClientHello中的servername，寻找所有主机中的key
    pub fn enable_sni(self) -> QuicServerSniBuilder<TlsServerConfig> {
        let hosts = Arc::new(DashMap::new());
        QuicServerSniBuilder {
            addresses: self.addresses,
            restrict: self.restrict,
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
    /// 添加服务器，包括证书链、私钥、参数
    /// 可以调用多次，支持多服务器，支持TLS SNI
    /// 若是新连接的server_name没有对应的配置，则会被拒绝
    pub fn add_host(
        self,
        server_name: impl Into<String>,
        cert_file: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
    ) -> Self {
        let cert = std::fs::read(cert_file).unwrap();
        let cert_chain = vec![CertificateDer::from(cert)];

        let key = std::fs::read(key_file).unwrap();
        let key_der = PrivateKeyDer::try_from(key).unwrap();

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
}

impl QuicServerBuilder<TlsServerConfig> {
    pub fn with_alpn(mut self, alpn: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.tls_config.alpn_protocols.extend(alpn);
        self
    }

    pub fn listen(self) -> io::Result<ArcQuicServer> {
        let uscs = self
            .addresses
            .into_iter()
            .filter_map(|address| {
                let arc_usc = get_or_create_usc(&address).map_err(|e| log::error!("{e}"));
                Some((address, arc_usc.ok()?))
            })
            .collect::<HashMap<_, _>>();
        if uscs.is_empty() {
            let error = "all addresses are not available";
            let error = io::Error::new(io::ErrorKind::AddrNotAvailable, error);
            return Err(error);
        }

        let quic_server = ArcQuicServer(Arc::new(QuicServer {
            uscs,
            listener: Default::default(),
            _restrict: self.restrict,
            _supported_versions: self.supported_versions,
            _load_balance: self.load_balance,
            parameters: self.parameters,
            tls_config: Arc::new(self.tls_config),
            streams_controller: self.streams_controller,
            token_provider: self.token_provider,
        }));
        *SERVER.write().unwrap() = Arc::downgrade(&quic_server.0);
        Ok(quic_server)
    }
}

impl QuicServerSniBuilder<TlsServerConfig> {
    pub fn with_alpn(mut self, alpn: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.tls_config.alpn_protocols.extend(alpn);
        self
    }

    pub fn listen(self) -> io::Result<ArcQuicServer> {
        let uscs = self
            .addresses
            .into_iter()
            .filter_map(|address| {
                let arc_usc = get_or_create_usc(&address).map_err(|e| log::error!("{e}"));
                Some((address, arc_usc.ok()?))
            })
            .collect::<HashMap<_, _>>();
        if uscs.is_empty() {
            let error = "all addresses are not available";
            let error = io::Error::new(io::ErrorKind::AddrNotAvailable, error);
            return Err(error);
        }
        let quic_server = ArcQuicServer(Arc::new(QuicServer {
            uscs,
            listener: Default::default(),
            _restrict: self.restrict,
            _supported_versions: self.supported_versions,
            _load_balance: self.load_balance,
            parameters: self.parameters,
            tls_config: Arc::new(self.tls_config),
            streams_controller: self.streams_controller,
            token_provider: self.token_provider,
        }));
        *SERVER.write().unwrap() = Arc::downgrade(&quic_server.0);
        Ok(quic_server)
    }
}
