use std::{io, net::SocketAddr, sync::LazyLock};

use connection::QuicConnection;
use dashmap::DashMap;
use path::Pathway;
use qbase::{
    config::Parameters,
    packet::{InitialHeader, RetryHeader},
};
use qudp::ArcUsc;

// use path::Pathway;
// use qbase::packet::SpacePacket;

pub mod connection;
pub mod error;
pub mod path;
pub mod pipe;
pub mod router;
pub mod tls;

/// 发送报文的trait，但其实发送还有其他需要的形式，比如：
/// - 携带ttl设置发送
/// - sendmmsg/send_vectored，多个包一次系统调用发送，要求向同一个目标
///   - 配合GSO，携带segment size的形式 发送，内核发送优化，将是最高效的发送方法
pub trait Sendmsg {
    fn sendmsg(&mut self, msg: &[u8], dest: SocketAddr) -> std::io::Result<usize>;
}

/// 全局的usc注册管理，用于查找已有的usc，key是绑定的本地地址，包括v4和v6的地址
pub static USC_REGISTRY: LazyLock<DashMap<SocketAddr, ArcUsc>> = LazyLock::new(DashMap::new);
/// 全局的QuicConnection注册管理，用于查找已有的QuicConnection，key是初期的Pathway
/// 包括被动接收的连接和主动发起的连接
pub static CONNECTIONS: LazyLock<DashMap<Pathway, QuicConnection>> = LazyLock::new(DashMap::new);

/// 其实是一个Builder，最终得到一个ArcConnection
pub struct QuicClient {
    reuse_connection: bool,
}

impl QuicClient {
    /// 无论向哪里发起连接，都使用同一个本地的Usc，包括一对v4和v6的，这在P2P场景下很有用
    pub fn unique() -> Self {
        todo!()
    }

    /// 绑定一个地址，若该地址
    /// - 已经有了usc(UdpSocket controller)，且已在注册管理中，那就查找即可
    /// - 要是没有查到，那就新建一个usc，然后注册管理起来
    ///
    /// 为何是绑定一系列地址，因为QUIC本身就是支持多路径的。
    /// 况且，为了推广IPv6，通常都是IPv6、IPv4双栈的的Happly Eyeballs策略。
    ///
    /// # Examples
    /// ```
    /// use qconnection::QuicClient;
    /// use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    ///
    /// let mut client = QuicClient::bind([
    ///     "[2001:db8::1]:8080".parse().unwrap(),
    ///     "127.0.0.1:8080".parse().unwrap(),
    /// ]);
    /// client.reuse_connection();
    /// ```
    pub fn bind(_addresses: impl IntoIterator<Item = SocketAddr>) -> Self {
        // TODO: 完善逻辑
        Self {
            reuse_connection: false,
        }
    }

    /// 重新绑定地址，其后创建的连接，会使用新的绑定地址
    pub fn rebind(&mut self, _addresses: impl IntoIterator<Item = SocketAddr>) {
        todo!()
    }

    /// 在优先使用IPv6的情况下，可以设置一个IPv4的地址，以备IPv6无法使用时的备用
    /// 必须bind的地址中一个是v4，一个是v6，才有意义
    pub fn enable_happy_eyeballs(&mut self) -> &mut Self {
        todo!()
    }

    /// 是否高效复用连接，假如已经有了一个到server_name的连接，那再去连的话，就直接复用
    pub fn reuse_connection(&mut self) -> &mut Self {
        self.reuse_connection = true;
        self
    }

    /// 当服务端发来版本协商包，其中包含了支持的版本号，那么客户端可以选择使用哪个版本
    /// 将按照客户端设定的versions的顺序优先选择
    pub fn use_versions(&mut self, _versions: Vec<u32>) -> &mut Self {
        todo!()
    }

    /// 设值客户端连接参数。若不设置，则会使用一组默认参数。
    /// 后续使用该QuicClient创建新连接，会直接使用这些参数。
    /// 可以多次调用该函数，覆盖上一次设置的参数。
    pub fn with_parameters(&mut self, _parameters: Parameters) -> &mut Self {
        todo!()
    }

    /// 设置客户端的证书，用于传输给服务端验证客户端身份
    /// 一般情况下，客户端都无需设置证书，只有特别的安全需求，才需要客户端提交证书
    pub fn with_cert(&mut self) -> &mut Self {
        todo!()
    }

    /// 验证服务端证书，是否正常的方法
    pub fn with_auth(&mut self) -> &mut Self {
        todo!()
    }

    /// 设置TokenRegisty的方法，当收到服务端的NewToken，客户端自行决定如何保存。
    /// 如不设置，则会丢弃这些NewToken
    /// TokenSink会在创建新连接时，尝试根据server_name获取可用Token
    /// TokenSink还需保存服务端颁发的关联Token，以便未来连接时使用
    pub fn with_token_sink(&mut self) -> &mut Self {
        todo!()
    }

    /// 使用QuicClient的usc，去创建一个QuicConnection
    /// 需要注意，usc的地址是v4还是v6的，要跟server_addr保持一致
    /// server_name要填写在ClientHello中，
    /// server_addr是目标地址，虽然可以从server_name域名解析出来，但是指定使用哪一个，仍有开发者自己决定
    /// parameters是连接参数，将使用QuicClient中设置好的。
    /// token则根据[`with_token_registry`]设置的方法，来决定是否需要填写
    /// 创建好的连接，应要保存在全局QuicConnection集合中
    /// 那如果开启了reuse_connection选项，则会优先从该全局QuicConnection集合里获取到server_name的
    pub fn connect(
        &self,
        _server_name: String,
        _server_addr: SocketAddr,
    ) -> io::Result<QuicConnection> {
        todo!()
    }
}

/// 服务端的Quic连接，可以接受新的连接
/// 实际上服务端的性质，类似于收包。不管包从哪个usc来，都可以根据需要来创建
/// 要想有服务端的功能，得至少有一个usc可以收包。
/// 如果不创建QuicServer，那意味着不接收新连接
pub struct QuicServer {
    _usc: ArcUsc,
}

impl QuicServer {
    /// 指定绑定的地址，即服务端的usc的监听地址
    /// 监听地址可以有多个，但必须都得是本地能绑定成功的，否则会panic
    /// 监听地址若为空，则会默认创建一个
    /// 严格模式是指，只有在这些地址上收到并创建的新连接，才会被接受
    pub fn bind(_addresses: impl IntoIterator<Item = SocketAddr>, _restrict: bool) -> Self {
        todo!()
    }

    /// 获取所有监听的地址，因为客户端创建的每一个usc都可以成为监听端口
    pub fn listen_addresses(&self) -> Vec<SocketAddr> {
        todo!()
    }

    /// 设置服务端支持的版本，以供后续版本协商
    /// 当服务收到不支持的版本的Initial包时，会向客户端发送版本协商包，携带着服务端所有支持的版本号
    pub fn with_supported_versions(&mut self, _versions: Vec<u32>) -> &mut Self {
        todo!()
    }

    /// TokenProvider有2个功能：
    /// TokenProvider需要向客户端颁发新Token
    /// 同时，收到新连接，TokenProvider也要验证客户端的Initial包中的Token
    pub fn with_token_provider(&mut self, _validator: impl Fn(String, &[u8]) -> bool) -> &mut Self {
        todo!()
    }

    /// 如果服务端也想验证客户端的真实性的话，可以调用这个方法设置。
    /// 若不设置，则意味着不验证，常规服务器通常也不验证
    pub fn with_auth(&mut self) -> &mut Self {
        todo!()
    }

    /// 设置负载均衡器，当收到新连接的时候，是否需要为了负载均衡重定向到其他服务器
    /// 所谓负载均衡，就是收到新连接的Initial包，是否需要回复一个Retry，让客户端连接到新地址上
    pub fn with_load_balance(
        &mut self,
        _lb: impl Fn(InitialHeader) -> Option<RetryHeader>,
    ) -> &mut Self {
        todo!()
    }

    /// 添加服务器，包括证书链、私钥、参数
    /// 可以调用多次，支持多服务器，支持TLS SNI
    /// 若是新连接的server_name没有对应的配置，则会被拒绝
    pub fn add_host(
        &mut self,
        _server_name: String,
        _cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        _key_der: rustls::pki_types::PrivateKeyDer<'static>,
        _parameter: Parameters,
    ) {
        todo!()
    }

    /// 像是上述with_xxx的函数，都是Builder，最终listen得到一个QuicServer，可以接受新连接
    pub fn listen(&self) {
        todo!()
    }

    /// 监听新连接的到来
    /// 新连接可能通过本地的任何一个有效usc来创建
    /// 只有调用该函数，才会有被动创建的Connection存放队列，等待着应用层来处理
    pub async fn accept(&self) -> io::Result<(QuicConnection, SocketAddr)> {
        todo!()
    }
}

#[cfg(test)]
mod tests {}
