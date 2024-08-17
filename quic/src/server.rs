use std::{
    fs::File,
    io::{self, BufReader},
    net::SocketAddr,
    path::Path,
    sync::Arc,
};

use dashmap::DashMap;
use qbase::{
    config::Parameters,
    packet::{InitialHeader, RetryHeader},
};
use qconnection::connection::QuicConnection;
use rustls::{
    server::{danger::ClientCertVerifier, NoClientAuth, ResolvesServerCert, WantsServerCert},
    ConfigBuilder, ServerConfig as TlsServerConfig, WantsVerifier,
};

type TlsServerConfigBuilder<T> = ConfigBuilder<TlsServerConfig, T>;

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
    addresses: Vec<SocketAddr>,
    _restrict: bool,
    _supported_versions: Vec<u32>,
    _load_balance: Option<Arc<dyn Fn(InitialHeader) -> Option<RetryHeader>>>,
    _tls_config: Arc<TlsServerConfig>,
}

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
            load_balance: None,
            tls_config: TlsServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap(),
        }
    }

    /// 获取所有监听的地址，因为客户端创建的每一个usc都可以成为监听端口
    pub fn listen_addresses(&self) -> &Vec<SocketAddr> {
        &self.addresses
    }

    /// 监听新连接的到来
    /// 新连接可能通过本地的任何一个有效usc来创建
    /// 只有调用该函数，才会有被动创建的Connection存放队列，等待着应用层来处理
    pub async fn accept(&self) -> io::Result<(QuicConnection, SocketAddr)> {
        todo!()
    }
}

#[derive(Debug)]
struct Host {
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: Arc<dyn rustls::sign::SigningKey>,
    _parameter: Parameters,
}

pub struct QuicServerBuilder<T> {
    addresses: Vec<SocketAddr>,
    restrict: bool,
    supported_versions: Vec<u32>,
    load_balance: Option<Arc<dyn Fn(InitialHeader) -> Option<RetryHeader>>>,
    tls_config: T,
}

pub struct QuicServerSniBuilder<T> {
    addresses: Vec<SocketAddr>,
    restrict: bool,
    supported_versions: Vec<u32>,
    load_balance: Option<Arc<dyn Fn(InitialHeader) -> Option<RetryHeader>>>,
    hosts: Arc<DashMap<String, Host>>,
    tls_config: T,
}

impl<T> QuicServerBuilder<T> {
    pub fn with_supported_versions(
        &mut self,
        versions: impl IntoIterator<Item = u32>,
    ) -> &mut Self {
        self.supported_versions.clear();
        self.supported_versions.extend(versions);
        self
    }

    /// 设置负载均衡器，当收到新连接的时候，是否需要为了负载均衡重定向到其他服务器
    /// 所谓负载均衡，就是收到新连接的Initial包，是否需要回复一个Retry，让客户端连接到新地址上
    pub fn with_load_balance(
        &mut self,
        load_balance: Arc<dyn Fn(InitialHeader) -> Option<RetryHeader>>,
    ) -> &mut Self {
        self.load_balance = Some(load_balance);
        self
    }

    /// TokenProvider有2个功能：
    /// TokenProvider需要向客户端颁发新Token
    /// 同时，收到新连接，TokenProvider也要验证客户端的Initial包中的Token
    pub fn with_token_provider(&mut self) -> &mut Self {
        // TODO: 完善该函数
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
            addresses: self.addresses,
            restrict: self.restrict,
            supported_versions: self.supported_versions,
            load_balance: self.load_balance,
            tls_config: self
                .tls_config
                .with_client_cert_verifier(client_cert_verifier),
        }
    }

    /// Disable client authentication.
    pub fn with_no_client_auth(self) -> QuicServerBuilder<TlsServerConfigBuilder<WantsServerCert>> {
        QuicServerBuilder {
            addresses: self.addresses,
            restrict: self.restrict,
            supported_versions: self.supported_versions,
            load_balance: self.load_balance,
            tls_config: self
                .tls_config
                .with_client_cert_verifier(Arc::new(NoClientAuth)),
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
            tls_config: self
                .tls_config
                .with_single_cert(cert_chain, key_der)
                .expect("The private key was wrong encoded or failed validation"),
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
            tls_config: self
                .tls_config
                .with_single_cert_with_ocsp(cert_chain, key_der, ocsp)
                .expect("The private key was wrong encoded or failed validation"),
        }
    }

    /// 应该是自动调用它，根据ClientHello中的servername，寻找所有主机中的key
    pub fn with_sni_supported(self) -> QuicServerSniBuilder<TlsServerConfig> {
        let hosts = Arc::new(DashMap::new());
        QuicServerSniBuilder {
            addresses: self.addresses,
            restrict: self.restrict,
            supported_versions: self.supported_versions,
            load_balance: self.load_balance,
            tls_config: self
                .tls_config
                .with_cert_resolver(Arc::new(VirtualHosts(hosts.clone()))),
            hosts,
        }
    }
}

impl QuicServerSniBuilder<TlsServerConfig> {
    /// 添加服务器，包括证书链、私钥、参数
    /// 可以调用多次，支持多服务器，支持TLS SNI
    /// 若是新连接的server_name没有对应的配置，则会被拒绝
    pub fn add_host(
        &mut self,
        server_name: impl ToOwned<Owned = String>,
        cert_file: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
        parameter: Parameters,
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
        self.hosts.insert(
            server_name.to_owned(),
            Host {
                cert_chain,
                private_key,
                _parameter: parameter,
            },
        );
        self
    }
}

impl QuicServerBuilder<TlsServerConfig> {
    pub fn listen(self) -> QuicServer {
        // TODO: 创建好相应的监听usc
        QuicServer {
            addresses: self.addresses,
            _restrict: self.restrict,
            _supported_versions: self.supported_versions,
            _load_balance: self.load_balance,
            _tls_config: Arc::new(self.tls_config),
        }
    }
}

impl QuicServerSniBuilder<TlsServerConfig> {
    pub fn listen(self) -> QuicServer {
        // TODO: 创建好相应的监听usc
        QuicServer {
            addresses: self.addresses,
            _restrict: self.restrict,
            _supported_versions: self.supported_versions,
            _load_balance: self.load_balance,
            _tls_config: Arc::new(self.tls_config),
        }
    }
}
