use std::{
    any::Any,
    borrow::Cow,
    future::{Future, poll_fn},
    io::{self, IoSlice},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
use derive_more::Deref;
use qbase::{
    net::{
        addr::{BindUri, RealAddr},
        route::{PacketHeader, SocketEndpointAddr},
    },
    util::ArcAsyncDeque,
};
use qinterface::{QuicIO, factory::ProductQuicIO};
use qudp::{BATCH_SIZE, UdpSocketController};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    nat,
    packet::{Header, StunHeader, WriteStunHeader, be_header},
};

pub type ArcRecvQueue = ArcAsyncDeque<(BytesMut, Pathway, Link)>;
use std::sync::OnceLock;

use crate::{Link, Pathway, nat::StunIO};

#[derive(Clone)]
pub struct TraversalFactory {
    agents: Cow<'static, [SocketAddr]>,
}

#[derive(Debug, thiserror::Error)]
pub enum InitialGlobalFactoryError {
    #[error("TraversalFactory has already been initialized with different STUN agents")]
    AlreadyInitialized,
}

static GLOBAL_FACTORY: OnceLock<Arc<TraversalFactory>> = OnceLock::new();

impl TraversalFactory {
    fn with(agents: impl Into<Cow<'static, [SocketAddr]>>) -> Self {
        Self {
            agents: agents.into(),
        }
    }

    pub fn initialize_global(
        agents: impl Into<Cow<'static, [SocketAddr]>>,
    ) -> Result<&'static Arc<TraversalFactory>, InitialGlobalFactoryError> {
        let agents: Cow<'static, [SocketAddr]> = agents.into();
        _ = GLOBAL_FACTORY.get_or_init(|| Arc::new(TraversalFactory::with(agents.clone())));
        match GLOBAL_FACTORY.get() {
            Some(factory) if factory.agents != agents => {
                Err(InitialGlobalFactoryError::AlreadyInitialized)
            }
            Some(factory) => Ok(factory),
            None => unreachable!("GLOBAL_FACTORY must have been initialized just now"),
        }
    }

    pub fn global() -> &'static Arc<Self> {
        GLOBAL_FACTORY
            .get()
            .expect("TraversalFactory is not initialized")
    }
}

impl ProductQuicIO for TraversalFactory {
    fn bind(&self, bind_uri: BindUri) -> Box<dyn QuicIO> {
        let socket_addr = SocketAddr::try_from(bind_uri.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let &agent = self
            .agents
            .iter()
            .find(|addr| addr.is_ipv4() == socket_addr.is_ipv4())
            .ok_or_else(|| {
                io::Error::other("No agent matching the IP family of the bound address was found")
            })?;

        let iface = TraversalQuicInterface::new(bind_uri.clone(), socket_addr, agent)?;
        // 自动启动探测，注意，如果是stun server 本身，是会探测失败的，需要外部设置 outter addr
        iface.start_detection();

        if let Some((_ip_family, device, _port)) = bind_uri.as_iface_bind_uri() {
            match iface.bind_device(device) {
                Ok(_) => {
                    tracing::debug!(target: "stun", device, %bind_uri, "Bind device for interface")
                }
                Err(error) => {
                    tracing::warn!(target: "stun", device, %bind_uri, ?error, "Failed to bind device for interface")
                }
            };
        }

        Ok(Box::new(iface))
    }
}

#[derive(Deref, Clone)]
pub struct TraversalQuicInterface {
    #[deref]
    iface: Arc<Interface>,
    bind_uri: BindUri,
    stun_protocol: Arc<nat::protocol::StunProtocol>,
    stun_client: nat::client::Client,
    recv_queue: ArcRecvQueue,
}

impl TraversalQuicInterface {
    pub fn new(
        bind: BindUri,
        socket_addr: SocketAddr,
        stun_server: SocketAddr,
    ) -> io::Result<Self> {
        // 1. 创建 Interface
        let iface = Arc::new(Interface::new(socket_addr, bind.clone())?);
        let recv_queue = iface.rcvd_quic_packets.clone();
        // 2. 创建 StunProtocol，传入 Arc<Interface>
        let stun_protocol = Arc::new(nat::protocol::StunProtocol::new(iface.clone()));
        // 3. 创建 Client
        let stun_client = nat::client::Client::new(stun_protocol.clone(), stun_server);
        Ok(Self {
            iface,
            bind_uri: bind,
            stun_protocol,
            stun_client,
            recv_queue,
        })
    }

    pub fn bind_device(&self, name: &str) -> io::Result<()> {
        self.iface.usc.bind_device(name)
    }

    pub fn start_detection(&self) {
        if self.bind_uri.is_temporary() {
            return;
        }

        let iface = self.clone();
        tokio::spawn(async move {
            _ = poll_fn(|cx| iface.poll_endpoint_addr(cx)).await;
        });

        let iface = self.clone();
        tokio::spawn(async move {
            _ = poll_fn(|cx| iface.poll_nat_type(cx)).await;
        });
    }
}

impl QuicIO for TraversalQuicInterface {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn bind_uri(&self) -> BindUri {
        self.bind_uri.clone()
    }

    fn max_segment_size(&self) -> io::Result<usize> {
        Ok(1500)
    }

    fn max_segments(&self) -> io::Result<usize> {
        Ok(BATCH_SIZE)
    }

    fn poll_send(
        &self,
        cx: &mut Context,
        ptks: &[io::IoSlice],
        hdr: PacketHeader,
    ) -> Poll<io::Result<usize>> {
        debug_assert_eq!(hdr.ecn(), None);
        let hdr = qudp::DatagramHeader::new(
            hdr.link().src().try_into().expect("Must be SocketAddr"),
            hdr.link().dst().try_into().expect("Must be SocketAddr"),
            hdr.ttl(),
            hdr.ecn(),
            hdr.seg_size(),
        );
        self.iface.usc().poll_send(cx, ptks, &hdr)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [BytesMut],
        hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>> {
        let mut count = 0;
        loop {
            match self.recv_queue.poll_pop(cx) {
                Poll::Ready(Some((packet, pathway, link))) => {
                    hdrs[count] = PacketHeader::new(
                        pathway.into(),
                        link.into(),
                        64,
                        None,
                        packet.len() as u16,
                    );
                    pkts[count] = packet;
                    count += 1;
                    if count >= pkts.len() {
                        return Poll::Ready(Ok(count));
                    }
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "recv queue is closed",
                    )));
                }
                Poll::Pending if count > 0 => {
                    return Poll::Ready(Ok(count));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }

    fn real_addr(&self) -> io::Result<RealAddr> {
        Ok(RealAddr::Internet(self.usc.local_addr()?))
    }

    fn poll_close(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        // 需要注意：JoinHandle::poll在poll_close返回Ready后不能再被调用，否则会panic
        // stun_client.poll_close会被多次调用，内部使用状态机避免重复关闭任务
        // iface.poll_close只会被调用一次，因此不需要使用状态机做处理
        ready!(self.stun_client.poll_close(cx));
        ready!(self.stun_protocol.poll_close(cx));
        ready!(self.iface.poll_close(cx));
        self.recv_queue.close();
        Poll::Ready(Ok(()))
    }
}

impl StunIO for TraversalQuicInterface {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.usc.local_addr()
    }

    fn stun_bind_uri(&self) -> BindUri {
        self.bind_uri.clone()
    }

    fn poll_stun_send(
        &self,
        cx: &mut Context,
        packet: BytesMut,
        link: Link,
    ) -> Poll<io::Result<usize>> {
        self.iface.poll_stun_send(cx, packet, link)
    }

    fn poll_stun_recv(&self, cx: &mut Context) -> Poll<io::Result<(BytesMut, Link)>> {
        self.iface.poll_stun_recv(cx)
    }

    fn poll_endpoint_addr(&self, cx: &mut Context) -> Poll<io::Result<SocketEndpointAddr>> {
        let agent = self.stun_client.agent()?;
        let outer = ready!(self.stun_client.poll_outer_addr(cx)?);
        Poll::Ready(Ok(SocketEndpointAddr::Agent { agent, outer }))
    }

    fn poll_nat_type(&self, cx: &mut Context) -> Poll<io::Result<u8>> {
        let nat_type = ready!(self.stun_client.poll_nat_type(cx))?;
        Poll::Ready(Ok(nat_type as u8))
    }

    fn stun_protocol(&self) -> io::Result<Arc<nat::protocol::StunProtocol>> {
        Ok(self.stun_protocol.clone())
    }
}

pub struct Interface {
    usc: Arc<UdpSocketController>,
    bind_uri: BindUri,
    rcvd_stun_packets: ArcRecvQueue,
    rcvd_quic_packets: ArcRecvQueue,
    task: Mutex<AbortOnDropHandle<()>>,
    outer_addr: Arc<Mutex<Option<SocketAddr>>>,
}

// udp receiving task
// 分流数据包到rcvd_stun_packets, rcvd_quic_packets

// interface context收包任务
// 从rcvd_quic_packets读取

impl Interface {
    pub fn new(local_addr: SocketAddr, bind_uri: BindUri) -> io::Result<Self> {
        let usc = Arc::new(UdpSocketController::bind(local_addr)?);
        let rcvd_stun_packets = ArcAsyncDeque::new();
        let rcvd_quic_packets = ArcAsyncDeque::new();
        let outer_addr = Arc::new(Mutex::new(None));

        let recving_task = {
            let stun_recv_queen = rcvd_stun_packets.clone();
            let quic_recv_queue = rcvd_quic_packets.clone();
            let usc = usc.clone();
            let outer_addr = outer_addr.clone();
            async move {
                let local_addr = usc.local_addr().unwrap();
                loop {
                    let mut reciver = usc.receiver();
                    let msg_count = match reciver.recv().await {
                        Ok(msg_count) => msg_count,
                        Err(error) => {
                            tracing::debug!(target: "stun", %error, "Recv error");
                            break;
                        }
                    };
                    for (hdr, mut buf) in
                        core::iter::zip(reciver.headers, reciver.iovecs).take(msg_count)
                    {
                        let link = Link::new(hdr.src, local_addr);
                        let pathway = Pathway::new(
                            SocketEndpointAddr::direct(local_addr),
                            SocketEndpointAddr::direct(hdr.src),
                        );
                        buf.truncate(hdr.seg_size as usize);
                        match be_header(&buf) {
                            Ok((remain, header)) => match header {
                                Header::Stun(_stun_header) => {
                                    let offset = buf.len() - remain.len();
                                    stun_recv_queen.push_back((
                                        buf.split_off(offset),
                                        pathway,
                                        link,
                                    ));
                                }
                                Header::Forward(forward_header) => {
                                    let pathway = forward_header.pathway();
                                    if let Some(dst) =
                                        Interface::should_forward(&outer_addr, pathway.local())
                                    {
                                        let _ = Interface::forward_to(&usc, dst, &buf).await;
                                    } else {
                                        let offset = buf.len() - remain.len();
                                        quic_recv_queue.push_back((
                                            buf.split_off(offset),
                                            pathway,
                                            link.flip(),
                                        ));
                                    }
                                }
                            },
                            Err(_) => {
                                quic_recv_queue.push_back((buf, pathway, link.flip()));
                            }
                        }
                    }
                }
            }
        };

        let recving_task =
            recving_task.instrument(tracing::info_span!(target: "stun", "recving_task",%bind_uri));
        let task = Mutex::new(AbortOnDropHandle::new(tokio::spawn(recving_task)));

        Ok(Self {
            usc,
            bind_uri,
            rcvd_stun_packets,
            rcvd_quic_packets,
            task,
            outer_addr,
        })
    }

    pub fn usc(&self) -> Arc<UdpSocketController> {
        self.usc.clone()
    }

    pub fn stun_recv_queen(&self) -> ArcRecvQueue {
        self.rcvd_stun_packets.clone()
    }

    pub fn set_outer_addr(&self, addr: SocketAddr) {
        *self.outer_addr.lock().unwrap() = Some(addr);
    }

    fn should_forward(
        outer_addr: &Arc<Mutex<Option<SocketAddr>>>,
        dst: SocketEndpointAddr,
    ) -> Option<SocketAddr> {
        let my_outer = (*outer_addr.lock().unwrap())?;
        if let SocketEndpointAddr::Agent {
            agent: dst_agent,
            outer: dst_outer,
        } = dst
        {
            match () {
                _ if my_outer == dst_agent => Some(dst_outer),
                _ if my_outer == dst_outer => None,
                // 添加循环检测：如果dst_agent等于dst_outer，说明会形成循环
                _ if dst_agent == dst_outer => {
                    tracing::warn!(target: "stun", 
                        "Detected loop forwarding: dst_agent == dst_outer ({})", dst_agent);
                    None
                }
                _ => Some(dst_agent),
            }
        } else {
            None
        }
    }

    async fn forward_to(
        iface: &Arc<UdpSocketController>,
        dst: SocketAddr,
        data: &[u8],
    ) -> io::Result<usize> {
        let hdr = qudp::DatagramHeader::new(iface.local_addr()?, dst, 64, None, data.len() as u16);
        let iovec = [IoSlice::new(data)];
        poll_fn(|cx| iface.poll_send(cx, &iovec, &hdr)).await
    }

    fn poll_close(&self, cx: &mut Context) -> Poll<()> {
        // 任务不会被再次拉起，因此不需要像StunClient一样设置状态机
        // poll_close返回Poll::Ready后，poll_close不可能再被调用，所以不需要take出任务
        let mut task = self.task.lock().unwrap();
        task.abort();
        _ = ready!(Pin::new(&mut *task).poll(cx));
        self.rcvd_quic_packets.close();
        self.rcvd_stun_packets.close();
        Poll::Ready(())
    }
}

impl StunIO for Interface {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.usc().local_addr()
    }

    fn stun_bind_uri(&self) -> BindUri {
        self.bind_uri.clone()
    }

    fn poll_stun_send(
        &self,
        cx: &mut Context,
        mut packet: BytesMut,
        link: Link,
    ) -> Poll<io::Result<usize>> {
        let stun_hdr = StunHeader::new(0);
        let (mut hdr, _) = packet.split_at_mut(StunHeader::encoding_size());
        hdr.put_stun_header(&stun_hdr);
        let hdr = qudp::DatagramHeader::new(link.src(), link.dst(), 64, None, 0);
        self.usc().poll_send(cx, &[IoSlice::new(&packet)], &hdr)
    }

    fn poll_stun_recv(&self, cx: &mut Context) -> Poll<io::Result<(BytesMut, Link)>> {
        match ready!(self.stun_recv_queen().poll_pop(cx)) {
            Some((packet, _pathway, link)) => Poll::Ready(Ok((packet, link))),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "recv queue is closed",
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use qinterface::logical::QuicInterfaces;

    use super::*;

    #[tokio::test]
    async fn test_bind_interface_stun_functionality() {
        let agent = "127.0.0.1:12345".parse().unwrap();
        let _ = TraversalFactory::initialize_global(vec![agent]);

        let uri = BindUri::from("inet://127.0.0.1:0");

        let iface = QuicInterfaces::global()
            .bind(uri.clone(), TraversalFactory::global().clone())
            .await;

        let packet = BytesMut::from(&[0u8; 10][..]);
        let link = Link::new(
            "127.0.0.1:20000".parse().unwrap(),
            "127.0.0.1:30000".parse().unwrap(),
        );

        let result: std::io::Result<usize> = std::future::poll_fn(|cx| {
            iface
                .borrow()
                .unwrap()
                .poll_stun_send(cx, packet.clone(), link)
        })
        .await;

        assert!(result.is_ok());
    }
}
