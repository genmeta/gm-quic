use std::{
    convert::identity,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{
        Context,
        Poll::{self, Ready},
        ready,
    },
};

use bytes::BytesMut;
use qbase::{
    net::route::{PacketHeader, SocketEndpointAddr},
    util::ArcAsyncDeque,
};
use qinterface::{
    Interface, InterfaceExt, RefInterface,
    logical::{
        QuicInterface, WeakQuicInterface,
        component::{Component, RouterComponent},
    },
    route::Router,
};
use smallvec::SmallVec;
use tokio_util::task::AbortOnDropHandle;

pub type ArcRecvQueue = ArcAsyncDeque<(BytesMut, PathWay, Link)>;

use crate::{
    Link, PathWay,
    nat::{
        client::{StunClients, StunClientsComponent},
        router::{StunRouter, StunRouterComponent},
    },
    packet::{ForwardHeader, StunHeader},
};

#[derive(Debug, Clone)]
pub enum Forwarder<IO: RefInterface + 'static> {
    Clients { stun_clients: StunClients<IO> },
    Server { outer_addr: SocketAddr },
}

impl<IO: RefInterface> Forwarder<IO> {
    pub fn my_outers(&self) -> SmallVec<[SocketAddr; 8]> {
        match self {
            Forwarder::Clients { stun_clients } => stun_clients.with_clients(|clients| {
                clients
                    .values()
                    .filter_map(|client| client.get_outer_addr()?.ok())
                    .collect()
            }),
            Forwarder::Server { outer_addr } => SmallVec::from_iter([*outer_addr]),
        }
    }

    pub fn should_forward(&self, dst: SocketEndpointAddr) -> Option<SocketAddr> {
        let my_outers = self.my_outers();

        if my_outers.is_empty() {
            return None;
        }

        let SocketEndpointAddr::Agent { agent, outer } = dst else {
            return None;
        };

        for my_outer in my_outers {
            if my_outer == outer {
                return None;
            }

            if my_outer == agent {
                return Some(outer);
            }
        }

        Some(agent)
    }
}

#[derive(Debug)]
pub struct ForwardersComponent {
    forward: Mutex<Forwarder<WeakQuicInterface>>,
}

impl ForwardersComponent {
    pub fn new(forwarder: Forwarder<WeakQuicInterface>) -> Self {
        Self {
            forward: Mutex::new(forwarder),
        }
    }

    fn lock_forwarders(&self) -> MutexGuard<'_, Forwarder<WeakQuicInterface>> {
        self.forward.lock().expect("Forwarder lock poisoned")
    }

    pub fn forwarder(&self) -> Forwarder<WeakQuicInterface> {
        self.lock_forwarders().clone()
    }
}

impl Component for ForwardersComponent {
    fn poll_shutdown(&self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }

    fn reinit(&self, quic_iface: &QuicInterface) {
        _ = quic_iface.with_component(|clients: &StunClientsComponent| {
            clients.reinit(quic_iface);
            *self.lock_forwarders() = Forwarder::Clients {
                stun_clients: clients.clone(),
            };
        });
    }
}

#[derive(Debug)]
pub struct ReceiveAndDeliverPacket {
    task: Mutex<Option<AbortOnDropHandle<io::Result<()>>>>,
    quic: bool,
    stun: bool,
    forward: bool,
}

#[bon::bon]
impl ReceiveAndDeliverPacket {
    #[builder(finish_fn = init)]
    pub fn new(
        #[builder(start_fn)] quic_iface: &QuicInterface,

        #[builder(default = true)] quic: bool,
        #[builder(default = true)] stun: bool,
        #[builder(default = true)] forward: bool,
    ) -> Self {
        let this = Self {
            task: Mutex::new(None),
            quic,
            stun,
            forward,
        };
        this.init(quic_iface);
        this
    }

    #[builder(finish_fn = spawn)]
    pub fn task<IO: RefInterface + 'static>(
        quic_router: Option<Arc<Router>>,
        stun_routers: Option<StunRouter>,
        forwarder: Option<Forwarder<IO>>,
        iface_ref: IO,
    ) -> AbortOnDropHandle<io::Result<()>> {
        AbortOnDropHandle::new(tokio::spawn(async move {
            let iface = iface_ref.iface();
            let bind_uri = iface.bind_uri();

            let deliver_quic_packet = async |pkt: BytesMut, hdr: PacketHeader| {
                let Some(quic_router) = quic_router.as_ref() else {
                    return;
                };

                use qbase::packet::{self, Packet, PacketReader};
                fn is_initial_packet(pkt: &Packet) -> bool {
                    matches!(pkt, Packet::Data(packet) if matches!(packet.header, packet::DataHeader::Long(packet::long::DataHeader::Initial(..))))
                }

                let size = pkt.len();
                let bind_uri = bind_uri.clone();
                for (packet, way) in PacketReader::new(pkt, 8)
                    .flatten()
                    .filter(move |pkt| !(is_initial_packet(pkt) && size < 1100))
                    .map(move |pkt| (pkt, (bind_uri.clone(), hdr.pathway(), hdr.link())))
                {
                    quic_router.deliver(packet, way).await;
                }
            };

            let deliver_stun_packet = async |mut pkt: BytesMut, hdr: PacketHeader| {
                let Some(stun_router) = stun_routers.as_ref() else {
                    return;
                };

                let (Ok(src), Ok(dst)) = (hdr.link().src().try_into(), hdr.link().dst().try_into())
                else {
                    return;
                };
                use crate::nat::msg::be_packet;
                let pkt = pkt.split_off(StunHeader::encoding_size());
                let Ok((.., (txid, packet))) = be_packet(&pkt) else {
                    return;
                };

                stun_router.deliver_stun_packet(txid, packet, Link::new(src, dst));
            };

            let deliver_forward_packet =
                async |mut pkt: BytesMut, hdr: PacketHeader, fhdr: ForwardHeader| {
                    if let Some(forwarder) = forwarder.as_ref()
                        && let Some(forward_target) =
                            forwarder.should_forward(fhdr.pathway().remote())
                    {
                        let bufs = &[io::IoSlice::new(&pkt)];
                        let link = Link::new(iface.real_addr()?, forward_target.into());
                        let hdr = PacketHeader::new(link.into(), link, 64, None, pkt.len() as _);
                        return iface.sendmmsg(bufs, hdr).await;
                    };

                    // split_off forward header, deliver the rest as quic packet
                    let pkt = pkt.split_off(ForwardHeader::encoding_size(&fhdr.pathway()));
                    deliver_quic_packet(pkt, hdr).await;
                    Ok(())
                };

            let (mut bufs, mut hdrs) = (vec![], vec![]);
            loop {
                use crate::packet::{Header, be_header};
                for (pkt, hdr) in iface.recvmmsg(&mut bufs, &mut hdrs).await? {
                    match be_header(&pkt) {
                        // quic
                        Err(_) => deliver_quic_packet(pkt, hdr).await,
                        // stun
                        Ok((_remain, Header::Stun(_stun_header))) => {
                            deliver_stun_packet(pkt, hdr).await
                        }
                        // forward
                        Ok((_remain, Header::Forward(forward_header))) => {
                            deliver_forward_packet(pkt, hdr, forward_header).await?
                        }
                    }
                }
            }
        }))
    }
}

impl ReceiveAndDeliverPacket {
    fn lock_task(&self) -> MutexGuard<'_, Option<AbortOnDropHandle<io::Result<()>>>> {
        self.task.lock().unwrap()
    }

    pub fn init(&self, quic_iface: &QuicInterface) {
        let (quic_router, stun_router, forwarder) = quic_iface.with_components(|components, _| {
            let quic_router = (self.quic)
                .then(|| components.with(RouterComponent::router))
                .and_then(identity);
            let stun_router = self
                .stun
                .then(|| components.with(StunRouterComponent::router))
                .and_then(identity);
            let forwarder = self
                .forward
                .then(|| components.with(ForwardersComponent::forwarder))
                .and_then(identity);
            (quic_router, stun_router, forwarder)
        });
        *self.lock_task() = Some(
            Self::task()
                .maybe_quic_router(quic_router)
                .maybe_stun_routers(stun_router)
                .maybe_forwarder(forwarder)
                .iface_ref(quic_iface.downgrade())
                .spawn(),
        );
    }
}

impl Component for ReceiveAndDeliverPacket {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> std::task::Poll<()> {
        let mut task_guard = self.lock_task();
        if let Some(task) = task_guard.as_mut() {
            task.abort();
            _ = ready!(Pin::new(task).poll(cx));
            *task_guard = None;
        }
        Ready(())
    }

    fn reinit(&self, quic_iface: &QuicInterface) {
        self.init(quic_iface);
    }
}
