use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{
        Arc, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use dashmap::{DashMap, mapref::entry::Entry};
pub use qbase::datagram::stun::{
    Attribute as Attr, BindingRequest, BindingRequest as Request, BindingResponse,
    BindingResponse as Response, Message, MessageType, TransactionId, Type, WriteStunMessage,
    WriteStunType, WriteTransactionId, be_stun_message, be_stun_type, be_transaction_id,
};
use qbase::{
    ArcReceiving, Cancelled,
    datagram::{Datagram, WriteDatagram},
    net::{
        NatType, NetFeature,
        route::{Line, Link},
    },
};
use thiserror::Error;
use tokio::time::timeout;

use crate::socket::UdpSocket;

const PROBE_ATTEMPTS: u8 = 30;
const FILTER_ATTEMPTS: u8 = 3;
const PROBE_TIMEOUT: Duration = Duration::from_millis(300);

type RequestHandler = dyn Fn(&Request, Link) -> Option<Response> + Send + Sync + 'static;

#[derive(Debug, Error)]
pub enum StunError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Reset(#[from] Cancelled),
    #[error("invalid STUN header")]
    InvalidHeader,
    #[error("STUN transaction response has already been read")]
    Completed,
}

pub struct Transaction {
    txid: TransactionId,
    protocol: Arc<StunProtocol>,
    receving: ArcReceiving<(Link, Response)>,
}

impl Transaction {
    pub fn id(&self) -> TransactionId {
        self.txid
    }

    pub async fn request(
        &mut self,
        link: Link,
        request: Request,
    ) -> Result<(Link, Response), StunError> {
        self.protocol.send_request(self.txid, link, request).await?;
        (&mut self.receving).await?.ok_or(StunError::Completed)
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        self.protocol.transactions.remove(&self.txid);
    }
}

pub struct StunProtocol {
    transactions: DashMap<TransactionId, ArcReceiving<(Link, Response)>>,
    sockets: DashMap<SocketAddr, Weak<UdpSocket>>,
    server_enabled: Arc<AtomicBool>,
    request_handler: RwLock<Option<Arc<RequestHandler>>>,
}

impl Default for StunProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl StunProtocol {
    pub fn new() -> Self {
        Self {
            transactions: DashMap::new(),
            sockets: DashMap::new(),
            server_enabled: Arc::new(AtomicBool::new(false)),
            request_handler: RwLock::new(None),
        }
    }

    pub fn enable_server(&self, enabled: bool) {
        self.server_enabled.store(enabled, Ordering::Release);
    }

    pub fn server_enabled(&self) -> bool {
        self.server_enabled.load(Ordering::Acquire)
    }

    pub fn on_request(
        &self,
        handler: impl Fn(&Request, Link) -> Option<Response> + Send + Sync + 'static,
    ) {
        *self.request_handler.write().unwrap() = Some(Arc::new(handler));
    }

    pub fn new_transaction(self: &Arc<Self>) -> Transaction {
        loop {
            let transaction_id = TransactionId::random();
            if let Entry::Vacant(entry) = self.transactions.entry(transaction_id) {
                let response = ArcReceiving::default();
                entry.insert(response.clone());
                return Transaction {
                    txid: transaction_id,
                    protocol: self.clone(),
                    receving: response,
                };
            }
        }
    }

    /// Detects the first server's mapped address and this socket's NAT type.
    ///
    /// The concrete bound address must belong to a socket registered in this
    /// protocol's Dock. Keep it registered and avoid concurrent probes or other
    /// traffic to the discovery servers until detection finishes.
    ///
    /// Servers must support the project's STUN encoding and changed-source
    /// responses. Private-address detection requires three distinct server IPs.
    /// An unanswered initial probe returns `(None, NatType::Blocked)`. As in
    /// qtraversal, an unanswered final probe is classified as `Dynamic`; these
    /// timeout classifications can also reflect packet loss or server failure.
    /// The returned mapping is specific to the first server, particularly for
    /// `Symmetric` and `Dynamic` NATs. Later probe errors discard that mapping.
    pub async fn detect_nat(
        self: &Arc<Self>,
        local_addr: SocketAddr,
        stun_server: SocketAddr,
    ) -> Result<(Option<SocketAddr>, NatType), StunError> {
        if local_addr.ip().is_unspecified() || local_addr.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NAT detection requires a concrete bound socket address",
            )
            .into());
        }

        let Some(first) = probe(
            self,
            local_addr,
            stun_server,
            Request::default(),
            PROBE_ATTEMPTS,
        )
        .await?
        else {
            return Ok((None, NatType::Blocked));
        };
        let outer_addr = first.map_addr()?;
        let server2 = first.changed_addr()?;
        if server2.ip() == stun_server.ip() || server2.port() == stun_server.port() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CHANGED-ADDRESS must change both IP and port",
            )
            .into());
        }
        let mut features = NetFeature::empty();

        let (filter_server, dynamic_server) = if outer_addr == local_addr {
            features |= NetFeature::Public;
            (stun_server, None)
        } else {
            let second = probe(
                self,
                local_addr,
                server2,
                Request::default(),
                PROBE_ATTEMPTS,
            )
            .await?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("NAT mapping probe to {server2} timed out"),
                )
            })?;

            if second.map_addr()? != outer_addr {
                return Ok((Some(outer_addr), NatType::Symmetric));
            }
            let server3 = second.changed_addr()?;
            if server3.ip() == stun_server.ip()
                || server3.ip() == server2.ip()
                || server3.port() == server2.port()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NAT detection requires a third IP and a changed port",
                )
                .into());
            }
            (server2, Some(server3))
        };

        // Preserve qtraversal's retry limits for public and private filtering.
        let attempts = if dynamic_server.is_some() {
            FILTER_ATTEMPTS
        } else {
            PROBE_ATTEMPTS
        };
        for (request, feature) in [
            (Request::change_ip_and_port(), NetFeature::Restricted),
            (Request::change_port(), NetFeature::PortRestricted),
        ] {
            if probe(self, local_addr, filter_server, request, attempts)
                .await?
                .is_none()
            {
                features |= feature;
            }
        }

        // Contacting server3 earlier would change the filtering test conditions.
        if let Some(server3) = dynamic_server {
            let response = probe(
                self,
                local_addr,
                server3,
                Request::default(),
                PROBE_ATTEMPTS,
            )
            .await?;
            match response {
                Some(response) if response.map_addr()? == outer_addr => {}
                _ => features |= NetFeature::Dynamic,
            }
        }

        Ok((Some(outer_addr), NatType::from(features)))
    }

    pub(crate) fn register_socket(&self, bound: SocketAddr, socket: &Arc<UdpSocket>) {
        self.sockets.insert(bound, Arc::downgrade(socket));
    }

    pub(crate) fn unregister_socket(&self, bound: SocketAddr, socket: &Weak<UdpSocket>) {
        self.sockets
            .remove_if(&bound, |_, registered| Weak::ptr_eq(registered, socket));
    }

    fn socket(&self, bound: SocketAddr) -> Option<Arc<UdpSocket>> {
        let registered = self.sockets.get(&bound)?.clone();
        let socket = registered.upgrade();
        if socket.is_none() {
            self.unregister_socket(bound, &registered);
        }
        socket
    }

    async fn send_request(
        &self,
        transaction_id: TransactionId,
        link: Link,
        request: Request,
    ) -> io::Result<()> {
        let socket = self.socket(link.src).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no STUN socket bound to {}", link.src),
            )
        })?;
        send_datagram(&socket, transaction_id, Message::Request(request), link).await
    }

    pub async fn on_datagram(
        &self,
        socket: &Arc<UdpSocket>,
        transaction_id: TransactionId,
        message: Message,
        link: Link,
    ) -> io::Result<()> {
        match message {
            Message::Response(body) => {
                let response = self
                    .transactions
                    .get(&transaction_id)
                    .map(|response| response.clone());
                if let Some(receiving) = response {
                    receiving.obtain((link, body));
                }
            }
            Message::Request(body) => {
                if !self.server_enabled() {
                    return Ok(());
                }
                let handler = self.request_handler.read().unwrap().clone();
                let Some(response) = handler.and_then(|handler| handler(&body, link)) else {
                    return Ok(());
                };
                send_datagram(socket, transaction_id, Message::Response(response), link).await?;
            }
        }
        Ok(())
    }
}

async fn probe(
    protocol: &Arc<StunProtocol>,
    local_addr: SocketAddr,
    server: SocketAddr,
    request: Request,
    attempts: u8,
) -> Result<Option<Response>, StunError> {
    use qbase::datagram::stun::{CHANGE_IP, CHANGE_PORT};

    let mut transaction = protocol.new_transaction();
    let link = Link::new(local_addr, server);
    for _ in 0..attempts {
        match timeout(PROBE_TIMEOUT, transaction.request(link, request.clone())).await {
            Ok(result) => {
                let (received, response) = result?;
                // Topology delivers links in local -> remote orientation.
                let source = received.dst;
                let flags = request.change_request().unwrap_or(0);
                let valid_ip = if flags & CHANGE_IP != 0 {
                    source.ip() != server.ip()
                } else {
                    source.ip() == server.ip()
                };
                let valid_port = if flags & CHANGE_PORT != 0 {
                    source.port() != server.port()
                } else {
                    source.port() == server.port()
                };
                if received.src != local_addr || !valid_ip || !valid_port {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected STUN response link: {received}"),
                    )
                    .into());
                }
                response.map_addr()?;
                if flags != 0 && response.source_addr()? != source {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "STUN SOURCE-ADDRESS does not match the packet source",
                    )
                    .into());
                }
                return Ok(Some(response));
            }
            Err(_) => continue,
        }
    }
    Ok(None)
}

fn encode_datagram(transaction_id: TransactionId, message: &Message) -> io::Result<BytesMut> {
    let mut buffer = BytesMut::with_capacity(128);
    buffer
        .put_datagram(&Datagram::Stun(transaction_id, message.clone()))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(buffer)
}

async fn send_datagram(
    socket: &UdpSocket,
    transaction_id: TransactionId,
    message: Message,
    link: Link,
) -> io::Result<()> {
    let buffer = encode_datagram(transaction_id, &message)?;
    let line = Line::new(
        link,
        Line::DEFAULT_TTL,
        None,
        buffer.len().min(u16::MAX as usize) as u16,
    );
    let slices = [IoSlice::new(&buffer)];
    if socket.send(&slices, line).await? == 1 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "STUN socket sent zero datagrams",
        ))
    }
}

#[cfg(test)]
mod tests {
    mod client;

    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::{
        dock::Dock,
        protocol::{ForwardProtocol, QuicProtocol},
        topology::Topology,
    };

    #[test]
    fn binding_request_encodes() {
        let txid = TransactionId::random();
        let message = Message::Request(Request::default());
        assert!(!encode_datagram(txid, &message).unwrap().is_empty());
    }

    #[test]
    fn transaction_is_registered_until_drop() {
        let protocol = Arc::new(StunProtocol::new());
        let transaction = protocol.new_transaction();
        let transaction_id = transaction.id();

        assert!(protocol.transactions.contains_key(&transaction_id));

        drop(transaction);

        assert!(!protocol.transactions.contains_key(&transaction_id));
    }

    #[test]
    fn new_transactions_do_not_overwrite_each_other() {
        let protocol = Arc::new(StunProtocol::new());
        let first = protocol.new_transaction();
        let second = protocol.new_transaction();

        assert_ne!(first.id(), second.id());
        assert_eq!(protocol.transactions.len(), 2);
    }

    #[tokio::test]
    async fn transaction_retries_with_the_same_id_after_timeout() {
        let protocol = Arc::new(StunProtocol::new());
        let topology = Arc::new(Topology::new(
            protocol.clone(),
            Arc::new(ForwardProtocol::new()),
            Arc::new(QuicProtocol::new()),
        ));
        let dock = Dock::new(topology);
        let client = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let agent = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let client_addr = client.local_addr().unwrap();
        let link = Link::new(client_addr, agent.local_addr().unwrap());
        dock.add(client).unwrap();
        dock.add(agent).unwrap();

        let mut transaction = protocol.new_transaction();
        let transaction_id = transaction.id();
        assert!(
            timeout(
                Duration::from_millis(20),
                transaction.request(link, Request::default()),
            )
            .await
            .is_err()
        );
        assert_eq!(transaction.id(), transaction_id);

        protocol
            .on_request(move |_, link| Some(Response::with(vec![Attr::MappedAddress(link.dst)])));
        protocol.enable_server(true);
        let (response_link, response) = timeout(
            Duration::from_secs(1),
            transaction.request(link, Request::default()),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(response_link, link);
        assert_eq!(response.map_addr().unwrap(), client_addr);
        assert!(protocol.transactions.contains_key(&transaction_id));

        drop(transaction);

        assert!(!protocol.transactions.contains_key(&transaction_id));
    }
}
