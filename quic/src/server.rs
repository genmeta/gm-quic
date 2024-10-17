mod incoming;

use std::{
    io,
    net::SocketAddr,
    path::Path,
    sync::{Arc, LazyLock, RwLock},
};

use dashmap::DashMap;
pub use incoming::Incoming;
use qbase::{
    config::{Parameters, ServerParameters},
    packet::{long, DataHeader, DataPacket},
    token::TokenProvider,
    util::ArcAsyncDeque,
};
use qconnection::path::Pathway;
use qudp::ArcUsc;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{danger::ClientCertVerifier, NoClientAuth, ResolvesServerCert, WantsServerCert},
    ConfigBuilder, ServerConfig as TlsServerConfig, WantsVerifier,
};

use crate::get_or_create_usc;

type TlsServerConfigBuilder<T> = ConfigBuilder<TlsServerConfig, T>;
type QuicListener = ArcAsyncDeque<(DataPacket, Pathway, ArcUsc)>;

/// 理应全局只有一个server
static SERVER: LazyLock<RwLock<Option<QuicServer>>> = LazyLock::new(RwLock::default);

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
struct RawQuicServer {
    addresses: Vec<SocketAddr>,
    listener: QuicListener,
    _restrict: bool,
    _supported_versions: Vec<u32>,
    _parameters: DashMap<String, Parameters>,
    tls_config: Arc<TlsServerConfig>,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

#[derive(Clone)]
pub struct QuicServer(Arc<RawQuicServer>);

impl QuicServer {
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
            parameters: DashMap::new(),
            tls_config: TlsServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap(),
            token_provider: None,
        }
    }

    pub fn addresses(&self) -> &[SocketAddr] {
        &self.0.addresses
    }

    /// 监听新连接的到来
    /// 新连接可能通过本地的任何一个有效usc来创建
    /// 只有调用该函数，才会有被动创建的Connection存放队列，等待着应用层来处理
    pub async fn accpet(&self) -> io::Result<Incoming<'_>> {
        let listening_stopped = || io::Error::new(io::ErrorKind::Other, "listening stopped");
        let (packet, way, usc) = self.0.listener.pop().await.ok_or_else(listening_stopped)?;
        Ok(Incoming::new(packet, way, usc, &self.0))
    }

    pub(crate) fn try_to_accept_conn_from(packet: DataPacket, pathway: Pathway, usc: &ArcUsc) {
        let server = SERVER.read().unwrap();
        let Some(server) = server.as_ref().map(|s| &s.0) else {
            return;
        };

        match &packet.header {
            DataHeader::Long(long::DataHeader::Initial(_))
            | DataHeader::Long(long::DataHeader::ZeroRtt(_)) => {}
            _ => return,
        };

        server.listener.push_back((packet, pathway, usc.clone()));
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
    parameters: DashMap<String, Parameters>,
    tls_config: T,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

pub struct QuicServerSniBuilder<T> {
    addresses: Vec<SocketAddr>,
    restrict: bool,
    supported_versions: Vec<u32>,
    hosts: Arc<DashMap<String, Host>>,
    parameters: DashMap<String, Parameters>,
    tls_config: T,
    token_provider: Option<Arc<dyn TokenProvider>>,
}

impl<T> QuicServerBuilder<T> {
    pub fn with_supported_versions(mut self, versions: impl IntoIterator<Item = u32>) -> Self {
        self.supported_versions.clear();
        self.supported_versions.extend(versions);
        self
    }

    /// TokenProvider有2个功能：
    /// TokenProvider需要向客户端颁发新Token
    /// 同时，收到新连接，TokenProvider也要验证客户端的Initial包中的Token
    pub fn with_token_provider(mut self, token_provider: Arc<dyn TokenProvider>) -> Self {
        self.token_provider = Some(token_provider);
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
            addresses: self.addresses,
            restrict: self.restrict,
            supported_versions: self.supported_versions,
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_cert_verifier(client_cert_verifier),
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
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_client_cert_verifier(Arc::new(NoClientAuth)),
            token_provider: self.token_provider,
        }
    }
}

impl QuicServerBuilder<TlsServerConfigBuilder<WantsServerCert>> {
    /// 设值服务端连接参数。若不设置，则会使用一组默认参数。
    /// 后续接受新的连接，会直接使用这些参数。不过在sni模式下，各个host可以有不同的参数，该函数将失去意义。
    /// 因此，它最好配合[`with_single_cert`]或者[`with_single_cert_with_ocsp`]一起使用
    /// 可以多次调用该函数，会覆盖上一次设置的参数。
    ///
    /// [`with_single_cert`]: QuicServerBuilder::with_single_cert
    /// [`with_single_cert_with_ocsp`]: QuicServerBuilder::with_single_cert_with_ocsp
    pub fn with_parameters(self, parameters: ServerParameters) -> Self {
        self.parameters.insert("*".to_owned(), parameters.into());
        self
    }

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
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_single_cert(cert_chain, key_der)
                .expect("The private key was wrong encoded or failed validation"),
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
            parameters: self.parameters,
            tls_config: self
                .tls_config
                .with_single_cert_with_ocsp(cert_chain, key_der, ocsp)
                .expect("The private key was wrong encoded or failed validation"),
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
            parameters: DashMap::new(),
            tls_config: self
                .tls_config
                .with_cert_resolver(Arc::new(VirtualHosts(hosts.clone()))),
            hosts,
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
        parameters: Parameters,
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
        self.parameters.insert(server_name.clone(), parameters);
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

    pub fn listen(self) -> QuicServer {
        for addr in &self.addresses {
            if let Err(e) = get_or_create_usc(addr) {
                log::error!("faild to listen on {addr}: {e}");
            }
        }
        let quic_server = QuicServer(Arc::new(RawQuicServer {
            addresses: self.addresses,
            listener: QuicListener::new(),
            _restrict: self.restrict,
            _supported_versions: self.supported_versions,
            _parameters: self.parameters,
            tls_config: Arc::new(self.tls_config),
            token_provider: self.token_provider,
        }));
        *SERVER.write().unwrap() = Some(quic_server.clone());
        quic_server
    }
}

impl QuicServerSniBuilder<TlsServerConfig> {
    pub fn with_alpn(mut self, alpn: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.tls_config.alpn_protocols.extend(alpn);
        self
    }

    pub fn listen(self) -> QuicServer {
        for addr in &self.addresses {
            if let Err(e) = get_or_create_usc(addr) {
                log::error!("faild to listen on {addr}: {e}");
            }
        }
        let quic_server = QuicServer(Arc::new(RawQuicServer {
            addresses: self.addresses,
            listener: QuicListener::new(),
            _restrict: self.restrict,
            _supported_versions: self.supported_versions,
            _parameters: self.parameters,
            tls_config: Arc::new(self.tls_config),
            token_provider: self.token_provider,
        }));
        *SERVER.write().unwrap() = Some(quic_server.clone());
        quic_server
    }
}
