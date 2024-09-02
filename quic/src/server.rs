use std::{
    fs::File,
    io::{self, BufReader},
    net::SocketAddr,
    path::Path,
    sync::Arc,
};

use dashmap::DashMap;
use deref_derive::Deref;
use futures::SinkExt;
use qbase::{
    cid::ConnectionId,
    config::{Parameters, ServerParameters},
    packet::{header::GetScid, long, DataHeader, DataPacket, InitialHeader, RetryHeader},
    token::{ArcTokenRegistry, TokenProvider},
    util::ArcAsyncDeque,
};
use qconnection::{connection::ArcConnection, path::Pathway, router::ROUTER};
use qudp::ArcUsc;
use rustls::{
    server::{danger::ClientCertVerifier, NoClientAuth, ResolvesServerCert, WantsServerCert},
    ConfigBuilder, ServerConfig as TlsServerConfig, WantsVerifier,
};

use crate::{get_usc_or_create, ConnKey, QuicConnection, CONNECTIONS, SERVER};

type TlsServerConfigBuilder<T> = ConfigBuilder<TlsServerConfig, T>;
type QuicListner = ArcAsyncDeque<(QuicConnection, SocketAddr)>;

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
pub struct RawQuicServer {
    addresses: Vec<SocketAddr>,
    listener: QuicListner,
    _restrict: bool,
    _supported_versions: Vec<u32>,
    _load_balance: Arc<dyn Fn(InitialHeader) -> Option<RetryHeader> + Send + Sync + 'static>,
    _parameters: DashMap<String, Parameters>,
    tls_config: Arc<TlsServerConfig>,
    token_provider: Option<Arc<dyn TokenProvider + Send + Sync + 'static>>,
}

#[derive(Clone, Deref)]
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
            load_balance: Arc::new(|_| None),
            parameters: DashMap::new(),
            tls_config: TlsServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap(),
            token_provider: None,
        }
    }
}

impl RawQuicServer {
    /// 获取所有监听的地址，因为客户端创建的每一个usc都可以成为监听端口
    pub fn listen_addresses(&self) -> &Vec<SocketAddr> {
        &self.addresses
    }

    pub fn initial_server_keys(&self, dcid: ConnectionId) -> rustls::quic::Keys {
        let suite = self
            .tls_config
            .crypto_provider()
            .cipher_suites
            .iter()
            .find_map(|cs| match (cs.suite(), cs.tls13()) {
                (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => {
                    Some(suite.quic_suite())
                }
                _ => None,
            })
            .flatten()
            .unwrap();
        suite.keys(&dcid, rustls::Side::Server, rustls::quic::Version::V1)
    }

    pub fn recv_unmatched_packet(&self, packet: DataPacket, pathway: Pathway, usc: &ArcUsc) {
        let (index, initial_dcid) = match &packet.header {
            DataHeader::Long(hdr @ long::DataHeader::Initial(_)) => (0, *hdr.get_scid()),
            DataHeader::Long(hdr @ long::DataHeader::ZeroRtt(_)) => (1, *hdr.get_scid()),
            _ => return,
        };
        let initial_scid =
            std::iter::repeat_with(|| ConnectionId::random_gen_with_mark(8, 0, 0x7F))
                .find(|cid| !CONNECTIONS.contains_key(&ConnKey::Server(*cid)))
                .unwrap();

        let token_provider = match &self.token_provider {
            Some(provider) => ArcTokenRegistry::with_provider(provider.clone()),
            None => ArcTokenRegistry::default_provider(),
        };

        let initial_keys = self.initial_server_keys(initial_dcid);
        let inner = ArcConnection::new_server(
            initial_scid,
            initial_dcid,
            &Parameters::default(), // &self.parameters,
            initial_keys,
            self.tls_config.clone(),
            token_provider,
        );
        let conn = QuicConnection {
            key: ConnKey::Server(initial_scid),
            inner,
        };
        self.listener.push((conn.clone(), pathway.remote_addr()));
        if let Some(mut entry) = ROUTER.get_mut(&initial_scid) {
            _ = entry[index].send((packet, pathway, usc.clone()));
        };
    }

    /// 监听新连接的到来
    /// 新连接可能通过本地的任何一个有效usc来创建
    /// 只有调用该函数，才会有被动创建的Connection存放队列，等待着应用层来处理
    pub async fn accept(&self) -> io::Result<(QuicConnection, SocketAddr)> {
        let ret = self.listener.pop().await;
        if let Some((conn, addr)) = ret {
            return Ok((conn, addr));
        }
        Err(io::Error::new(
            io::ErrorKind::Other,
            "No connection available",
        ))
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
    parameters: DashMap<String, Parameters>,
    tls_config: T,
    token_provider: Option<Arc<dyn TokenProvider + Send + Sync + 'static>>,
}

pub struct QuicServerSniBuilder<T> {
    addresses: Vec<SocketAddr>,
    restrict: bool,
    supported_versions: Vec<u32>,
    load_balance: Arc<dyn Fn(InitialHeader) -> Option<RetryHeader> + Send + Sync + 'static>,
    hosts: Arc<DashMap<String, Host>>,
    parameters: DashMap<String, Parameters>,
    tls_config: T,
    token_provider: Option<Arc<dyn TokenProvider + Send + Sync + 'static>>,
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
            token_provider: self.token_provider,
        }
    }
}

impl QuicServerBuilder<TlsServerConfigBuilder<WantsServerCert>> {
    /// 设值服务端连接参数。若不设置，则会使用一组默认参数。
    /// 后续接受新的连接，会直接使用这些参数。不过在sni模式下，各个host可以有不同的参数，该函数将失去意义。
    /// 因此，它最好配合[`with_single_cert`]或者[`with_single_cert_with_ocsp`]一起使用
    /// 可以多次调用该函数，会覆盖上一次设置的参数。
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
        let cert_chain = rustls_pemfile::certs(&mut BufReader::new(
            File::open(cert_file).expect("Failed to open cert file"),
        ))
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to read and extract cert from the cert file");

        let key_der = rustls_pemfile::private_key(&mut BufReader::new(
            File::open(key_file).expect("Failed to open private key file"),
        ))
        .expect("Failed to read PEM sections from the private key file")
        .unwrap();

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
            token_provider: self.token_provider,
        }
    }

    pub fn with_single_cert_with_ocsp(
        self,
        cert_file: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
        ocsp: Vec<u8>,
    ) -> QuicServerBuilder<TlsServerConfig> {
        let cert_chain = rustls_pemfile::certs(&mut BufReader::new(
            File::open(cert_file).expect("Failed to open cert file"),
        ))
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to read and extract cert from the cert file");

        let key_der = rustls_pemfile::private_key(&mut BufReader::new(
            std::fs::File::open(key_file).expect("Failed to open private key file"),
        ))
        .expect("Failed to read PEM sections from the private key file")
        .unwrap();

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
        &mut self,
        server_name: impl Into<String>,
        cert_file: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
        parameters: Parameters,
    ) -> &mut Self {
        let cert_chain = rustls_pemfile::certs(&mut BufReader::new(
            File::open(cert_file).expect("Failed to open cert file"),
        ))
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to read and extract cert from the cert file");

        let key_der = rustls_pemfile::private_key(&mut BufReader::new(
            std::fs::File::open(key_file).expect("Failed to open private key file"),
        ))
        .expect("Failed to read PEM sections from the private key file")
        .unwrap();

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
    pub fn listen(self) -> QuicServer {
        for addr in &self.addresses {
            _ = get_usc_or_create(addr);
        }
        let quic_server = QuicServer(Arc::new(RawQuicServer {
            addresses: self.addresses,
            listener: Default::default(),
            _restrict: self.restrict,
            _supported_versions: self.supported_versions,
            _load_balance: self.load_balance,
            _parameters: self.parameters,
            tls_config: Arc::new(self.tls_config),
            token_provider: self.token_provider,
        }));
        *SERVER.write().unwrap() = Some(quic_server.clone());
        quic_server
    }
}

impl QuicServerSniBuilder<TlsServerConfig> {
    pub fn listen(self) -> QuicServer {
        for addr in &self.addresses {
            _ = get_usc_or_create(addr);
        }
        let quic_server = QuicServer(Arc::new(RawQuicServer {
            addresses: self.addresses,
            listener: Default::default(),
            _restrict: self.restrict,
            _supported_versions: self.supported_versions,
            _load_balance: self.load_balance,
            _parameters: self.parameters,
            tls_config: Arc::new(self.tls_config),
            token_provider: self.token_provider,
        }));
        *SERVER.write().unwrap() = Some(quic_server.clone());
        quic_server
    }
}
