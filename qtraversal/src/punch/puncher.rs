use std::{
    collections::HashSet,
    convert::TryInto,
    io,
    net::SocketAddr,
    ops::Deref,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use dashmap::{DashMap, DashSet, Entry};
use qbase::{
    frame::{ReceiveFrame, SendFrame},
    net::{
        AddrFamily,
        route::{PacketHeader, SocketEndpointAddr},
        tx::Signals,
    },
    packet::{
        Package, PacketSpace, ProductHeader,
        header::short::OneRttHeader,
        io::{AssemblePacket, Packages, PadTo20},
    },
};
use qevent::telemetry::Instrument;
use qinterface::{
    Interface, WeakInterface,
    bind_uri::BindUri,
    component::route::{QuicRouter, QuicRouterComponent},
    io::{IO, IoExt, ProductIO},
    manager::InterfaceManager,
};
use qudp::DEFAULT_TTL;
use tokio::{task::AbortHandle, time::timeout};
use tracing::Instrument as _;

use crate::{
    Link, PathWay,
    addr::AddressBook,
    frame::{
        PunchPair, TraversalFrame, add_address::AddAddressFrame, collision::CollisionFrame,
        konck::KonckFrame, punch_done::PunchDoneFrame, punch_me_now::PunchMeNowFrame,
        remove_address::RemoveAddressFrame,
    },
    nat::{
        client::{NatType, StunClientComponent},
        router::StunRouterComponent,
    },
    punch::{
        predictor::{PacketSendFn, PortPredictor},
        tx::Transaction,
    },
    route::ReceiveAndDeliverPacket,
};

type StunClient<I = WeakInterface> = crate::nat::client::StunClient<I>;
// type StunProtocol<IO = WeakQuicInterface> = crate::nat::protocol::StunProtocol<I>;

// TTL
#[cfg(any(test, feature = "test-ttl"))]
pub const COLLISION_TTL: u8 = 1;
#[cfg(not(any(test, feature = "test-ttl")))]
pub const COLLISION_TTL: u8 = 5;
const KONCK_TTL: u8 = 64;

// Timeout
const KONCK_TIMEOUT_MS: u64 = 100;
const PUNCH_TIMEOUT_MS: u64 = 3000;
const PUNCH_ME_NOW_TIMEOUT_MS: u64 = 1000;
const COLLISION_TIMEOUT_MS: u64 = 3000;

// Quantity
const MAX_RETRIES: usize = 5;
const COLLISION_PORTS: u32 = 400;
const BIRTHDAY_ATTACK_PORTS: u32 = 300;

pub struct ArcPuncher<TX, PH, S>(Arc<Puncher<TX, PH, S>>);

impl<TX, PH, S> Clone for ArcPuncher<TX, PH, S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<TX, PH, S> ArcPuncher<TX, PH, S>
where
    TX: SendFrame<TraversalFrame> + Send + Sync + Clone + 'static,
    PH: ProductHeader<OneRttHeader> + Send + Sync + 'static,
    S: PacketSpace<OneRttHeader> + Send + Sync + 'static,
{
    pub fn new(
        broker: TX,
        product_header: PH,
        packet_space: Arc<S>,
        ifaces: Arc<InterfaceManager>,
        iface_factory: Arc<dyn ProductIO>,
        quic_router: Arc<QuicRouter>,
        stun_servers: Arc<[SocketAddr]>,
    ) -> Self {
        Self(Arc::new(Puncher::new(
            broker,
            product_header,
            packet_space,
            ifaces,
            iface_factory,
            quic_router,
            stun_servers,
        )))
    }
}

pub struct Puncher<TX, PH, S> {
    transaction: DashMap<Link, (AbortHandle, Arc<Transaction>)>,
    punch_history: DashSet<Link>,
    product_header: PH,
    packet_space: Arc<S>,
    ifaces: Arc<InterfaceManager>,
    iface_factory: Arc<dyn ProductIO>,
    quic_router: Arc<QuicRouter>,
    stun_servers: Arc<[SocketAddr]>,
    address_book: Mutex<AddressBook>,
    punch_ifaces: DashMap<BindUri, Interface>,
    broker: TX,
}

impl<TX, PH, S> Puncher<TX, PH, S>
where
    TX: SendFrame<TraversalFrame> + Send + Sync + Clone + 'static,
    PH: ProductHeader<OneRttHeader> + Send + Sync + 'static,
    S: PacketSpace<OneRttHeader> + Send + Sync + 'static,
{
    pub fn new(
        broker: TX,
        product_header: PH,
        packet_space: Arc<S>,
        ifaces: Arc<InterfaceManager>,
        iface_factory: Arc<dyn ProductIO>,
        quic_router: Arc<QuicRouter>,
        stun_servers: Arc<[SocketAddr]>,
    ) -> Self {
        Self {
            transaction: DashMap::new(),
            punch_history: DashSet::new(),
            product_header,
            packet_space,
            ifaces,
            iface_factory,
            quic_router,
            stun_servers,
            address_book: Mutex::new(AddressBook::default()),
            punch_ifaces: DashMap::new(),
            broker,
        }
    }

    pub async fn send_packet<P>(
        &self,
        iface: &(impl IO + ?Sized),
        link: Link,
        ttl: u8,
        packages: P,
    ) -> io::Result<()>
    where
        P: for<'b> Package<S::PacketAssembler<'b>>,
        PadTo20: for<'b> Package<S::PacketAssembler<'b>>,
    {
        let mut buffer = [0; 128];
        let sent_bytes = (|| {
            let mut packet = self
                .packet_space
                .new_packet(self.product_header.new_header()?, &mut buffer)?;
            packet.assemble_packet(&mut Packages((packages, PadTo20)))?;
            let (sent_bytes, _props) = packet.encrypt_and_protect_packet();
            Result::<_, Signals>::Ok(sent_bytes)
        })()
        .map_err(|s| io::Error::other(format!("Failed to assemble packet: {s:?}")))?;

        let hdr = PacketHeader::new(link.into(), link.into(), ttl, None, sent_bytes as u16);
        iface
            .sendmmsg(&[io::IoSlice::new(&buffer[..sent_bytes])], hdr)
            .await
    }

    async fn collision(
        &self,
        iface: &Interface,
        link: Link,
        punch_pair: Link,
        ttl: u8,
    ) -> io::Result<()>
    where
        PadTo20: for<'b> Package<S::PacketAssembler<'b>>,
        TraversalFrame: for<'b> Package<S::PacketAssembler<'b>>,
    {
        tracing::debug!(target: "punch", %punch_pair, %link, ttl, "Starting collision attack");
        let mut random_ports = HashSet::new();
        let dst = link.dst();
        let ip = dst.ip();
        while random_ports.len() < COLLISION_PORTS as usize {
            let port = rand::random::<u16>() % (u16::MAX - 1024) + 1024;
            let dst = SocketAddr::new(ip, port);
            if !random_ports.insert(port) {
                continue;
            }
            let link = Link::new(link.src(), dst);
            let frame = TraversalFrame::Collision(CollisionFrame::new(punch_pair));
            self.send_packet(iface, link, ttl, frame).await?;
        }
        Ok(())
    }
}

impl<TX, PH, S> Drop for Puncher<TX, PH, S> {
    fn drop(&mut self) {
        for entry in self.transaction.iter() {
            entry.value().0.abort();
        }
        self.transaction.clear();
        self.punch_history.clear();
        let futures: Vec<_> = self
            .punch_ifaces
            .iter()
            .map(|entry| self.ifaces.unbind(entry.key().clone()))
            .collect();
        if !futures.is_empty() {
            tokio::spawn(
                async move {
                    futures::future::join_all(futures).await;
                }
                .instrument_in_current()
                .in_current_span(),
            );
        }
        self.punch_ifaces.clear();
    }
}

impl<TX, PH, S> ArcPuncher<TX, PH, S>
where
    TX: SendFrame<TraversalFrame> + Send + Sync + Clone + 'static,
    PH: ProductHeader<OneRttHeader> + Send + Sync + 'static,
    S: PacketSpace<OneRttHeader> + Send + Sync + 'static,
    for<'b> TraversalFrame: Package<S::PacketAssembler<'b>>,
    for<'b> PadTo20: Package<S::PacketAssembler<'b>>,
{
    pub fn add_local_address(
        &self,
        bind_uri: BindUri,
        local_addr: SocketAddr,
        nat_type: NatType,
        tire: u32,
    ) -> io::Result<()> {
        if nat_type == NatType::Dynamic {
            let puncher = self.clone();
            let ifaces = self.0.ifaces.clone();
            let iface_factory = self.0.iface_factory.clone();
            let stun_servers = self.0.stun_servers.clone();
            let quic_router = self.0.quic_router.clone();

            let bind = bind_uri.clone();
            tokio::spawn(
                async move {
                    let (iface, stun_client) =
                        dynamic_iface(&bind_uri, &ifaces, &iface_factory, &quic_router, &stun_servers)
                            .await?;
                    puncher.0.punch_ifaces.insert(iface.bind_uri(), iface.clone());
                    let outer = stun_client.outer_addr().await?;

                    let mut address_book = puncher.0.address_book.lock().unwrap();
                    let frame =
                        address_book.add_local_address(bind.clone(), outer, tire, nat_type)?;
                    tracing::debug!(target: "punch", bind_uri = %bind, %outer, nat_type = ?nat_type, "Sending AddAddress frame for dynamic");
                    puncher
                        .0
                        .broker
                        .send_frame([TraversalFrame::AddAddress(frame)]);
                    Ok::<_, io::Error>(())
                }
                .instrument_in_current()
                .in_current_span(),
            );
            return Ok(());
        }
        let mut address_book = self.0.address_book.lock().unwrap();
        let frame = address_book.add_local_address(bind_uri.clone(), local_addr, tire, nat_type)?;
        tracing::debug!(target: "punch", bind_uri = %bind_uri, %local_addr, nat_type = ?nat_type, "Sending AddAddress frame");
        self.0
            .broker
            .send_frame([TraversalFrame::AddAddress(frame)]);
        Ok(())
    }

    pub fn add_local_endpoint(
        &self,
        bind: BindUri,
        addr: SocketEndpointAddr,
    ) -> io::Result<Vec<(BindUri, Link, PathWay)>> {
        let mut address_book = self.0.address_book.lock().unwrap();
        address_book.add_local_endpoint(bind.clone(), addr)?;
        let mut ways = Vec::new();
        for remote_ep in address_book.remote_endpoint().iter() {
            if let Ok(way) = self.resolve_punch_connection(&bind, &addr, remote_ep) {
                ways.push(way);
            }
        }
        Ok(ways)
    }

    pub fn add_peer_endpoint(
        &self,
        endpoint: SocketEndpointAddr,
    ) -> io::Result<Vec<(BindUri, Link, PathWay)>> {
        let mut address_book = self.0.address_book.lock().unwrap();
        address_book.add_peer_endpoint(endpoint)?;
        let mut ways = Vec::new();
        for (bind, local_ep) in address_book.local_endpoint().iter() {
            if let Ok(way) = self.resolve_punch_connection(bind, local_ep, &endpoint) {
                ways.push(way);
            }
        }
        Ok(ways)
    }

    pub fn remove_local_address(&self, addr: SocketAddr) -> io::Result<()> {
        let mut address_book = self.0.address_book.lock().unwrap();
        let frame = address_book.remove_local_address(addr)?;
        self.0
            .broker
            .send_frame([TraversalFrame::RemoveAddress(frame)]);
        Ok(())
    }

    fn recv_remove_address_frame(&self, remove_address_frame: &RemoveAddressFrame) {
        let mut address_book = self.0.address_book.lock().unwrap();
        address_book.remove_remote_address(remove_address_frame.deref().into_inner() as u32);
    }

    fn recv_add_address_frame(&self, add_address_frame: AddAddressFrame) -> io::Result<()> {
        // The lock on address_book must be released before accessing the transaction map
        // to avoid a deadlock with recv_punch_me_now, which holds the transaction lock
        // while trying to acquire the address_book lock.
        let (bind, local) = {
            let mut address_book = self.0.address_book.lock().unwrap();
            address_book.add_remote_address(add_address_frame)?;
            let (bind, local) = address_book.pick_local_address(&add_address_frame)?;
            (bind.clone(), local)
        };

        let punch_pair = Link::new(*local, *add_address_frame);
        if self.0.punch_history.contains(&punch_pair) {
            tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local.nat_type(), add_address_frame.nat_type()), "Punch already completed, skipping");
            return Ok(());
        }
        match self.0.transaction.entry(punch_pair) {
            Entry::Occupied(_) => {
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local.nat_type(), add_address_frame.nat_type()), "Dup transaction for punch pair");
                return Ok(());
            }
            Entry::Vacant(entry) => {
                let tx = Arc::new(Transaction::new());
                let task = tokio::spawn(
                    {
                        let puncher = self.clone();
                        let tx = tx.clone();
                        async move {
                            let result = puncher
                                .punch_actively(bind, &local, &add_address_frame, tx)
                                .await;
                            puncher.0.punch_history.insert(punch_pair);
                            puncher.0.transaction.remove(&punch_pair);
                            result
                        }
                    }
                    .instrument_in_current()
                    .in_current_span(),
                )
                .abort_handle();
                entry.insert((task, tx.clone()));
            }
        };
        Ok(())
    }

    fn recv_punch_me_now(
        &self,
        pathway: PathWay,
        punch_me_now_frame: PunchMeNowFrame,
    ) -> io::Result<()> {
        let punch_pair = punch_me_now_frame.punch_pair().unwrap().flip();
        if self.0.punch_history.contains(&punch_pair) {
            tracing::debug!(target: "punch", %punch_pair, "Punch already completed, skipping");
            return Ok(());
        }

        let crate_punch_task = || {
            let tx = Arc::new(Transaction::new());
            let task = tokio::spawn({
                let puncher = self.clone();
                let tx = tx.clone();
                let address_book = self.0.address_book.lock().unwrap();
                let (bind, local_address) = address_book
                    .get_local_address(&punch_me_now_frame.paired_with_seq_num())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "local address not matche")
                    })?;
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_address.nat_type(), punch_me_now_frame.nat_type()), "Received punch me now frame, start passive punch");
                async move {
                    let result = puncher
                        .punch_passively(bind, &local_address, &punch_me_now_frame, tx)
                        .await;
                    puncher.0.punch_history.insert(punch_pair);
                    puncher.0.transaction.remove(&punch_pair);
                    result
                }
                .instrument_in_current()
                .in_current_span()
            })
            .abort_handle();
            Ok::<_, io::Error>((task, tx.clone()))
        };

        match self.0.transaction.entry(punch_pair) {
            Entry::Occupied(mut entry) => {
                let (task, tx) = entry.get_mut();
                if pathway.local() < pathway.remote() {
                    task.abort();
                    // 创建被动打洞
                    let (task, tx) = crate_punch_task()?;
                    entry.insert((task, tx.clone()));
                    tracing::debug!(target: "punch", %punch_pair, "New passive transaction for punch pair");
                } else {
                    tracing::debug!(target: "punch", %punch_pair, "Using existing active transaction to respond to PunchMeNow");
                    _ = tx
                        .recv_frame(&(punch_pair, TraversalFrame::PunchMeNow(punch_me_now_frame)));
                }
            }
            Entry::Vacant(entry) => {
                let (task, tx) = crate_punch_task()?;
                entry.insert((task, tx.clone()));
                tracing::debug!(target: "punch", %punch_pair, "New passive transaction");
            }
        };

        Ok(())
    }

    async fn punch_actively(
        &self,
        bind_uri: BindUri,
        local: &AddAddressFrame,
        remote: &AddAddressFrame,
        tx: Arc<Transaction>,
    ) -> io::Result<()> {
        let local_nat = local.nat_type();
        let remote_nat = remote.nat_type();
        let bind_addr = SocketAddr::try_from(bind_uri.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let link = Link::new(bind_addr, *remote.deref());
        let punch_pair = Link::new(*local.deref(), *remote.deref());
        tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Starting active punch");

        let mut punch_me_now = PunchMeNowFrame::new(
            punch_pair,
            remote.seq_num(),
            *local.deref(),
            local.tire(),
            local_nat,
        );
        let ifaces = self.0.ifaces.clone();
        let dynamic_iface = {
            let ifaces = self.0.ifaces.clone();
            let iface_factory = self.0.iface_factory.clone();
            let quic_router = self.0.quic_router.clone();
            let stun_servers = self.0.stun_servers.clone();
            async move |bind_uri: &BindUri| {
                dynamic_iface(
                    bind_uri,
                    &ifaces,
                    &iface_factory,
                    &quic_router,
                    &stun_servers,
                )
                .await
            }
        };

        let broker = self.0.broker.clone();
        let punch_ifaces = &self.0.punch_ifaces;

        // local \ remote  ·FullCone    RestrictedCone    RestrictedPort  Symmetric    Dynamic
        // FullCone         1               6                 6              6          6
        // RestrictedCone   1               6                 6              6          6
        // RestrictedPort   1               6                 6              7          6
        // Symmetric        1               4                 3              /          8
        // Dynamic          1               5                 5              2          5

        // 1: Remote is FullCone
        // Send direct Konck to remote, expecting PunchDone.
        // 2: Local Dynamic, Remote Symmetric -> New Interface & Birthday Attack
        // Send PunchMeNow, expect PunchMeNow. After receiving, start collision, expect PunchDone.
        // 3: Local Symmetric, Remote RestrictedPort -> Birthday Attack
        // Send PunchMeNow, expect PunchMeNow. Use random socket collision, expect PunchDone.
        // 4: Local Symmetric, Remote RestrictedCone -> Reverse Punching
        // Send PunchMeNow, expect remote to open hole and respond PunchMeNow. Then send direct Konck, expect PunchDone.
        // 5: Local Dynamic
        // New Interface, detect external address. Then send PunchMeNow and Konck, expect PunchDone.
        // 6: General Punching
        // Send Konck with TTL and PunchMeNow. Expect Konck, then respond PunchDone.
        // 7: Local RestrictedPort, Remote Symmetric -> Birthday Attack (Hold Hole)
        // Send packets to 300 random ports, then notify with PunchMeNow. Expect Konck, then respond PunchDone.
        // 8: Local Symmetric, Remote Dynamic
        // Hold holes on 30 random ports, send PunchMeNow. Expect Collision, then respond PunchMeNow.
        // Repeat until 300 sockets used.
        use NatType::*;
        use TraversalFrame::*;
        let result: io::Result<()> = match (local_nat, remote_nat) {
            (Blocked, _) | (_, Blocked) | (Symmetric, Symmetric) => {
                return Err(io::Error::other("Unsupported nat type"));
            }
            // 1: Remote is FullCone
            // Send direct Konck to remote, expecting PunchDone.
            (_, FullCone) => {
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Strategy: Remote FullCone, sending direct Konck");
                let iface = ifaces
                    .borrow(&bind_uri)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                let time = Duration::from_millis(100);
                for i in 0..5 {
                    tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "Sending Konck expecting PunchDone or receiving Konck");
                    self.0
                        .send_packet(&iface, link, KONCK_TTL, Konck(KonckFrame::new(punch_pair)))
                        .await?;
                    let timeout_duration = time * (1 << i);
                    tokio::select! {
                        _ = tokio::time::sleep(timeout_duration) => {
                            // continue loop
                        }
                        _ = tx.recv_konck() => {
                            tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Received Konck, sending PunchDone");
                            broker.send_frame([PunchDone(PunchDoneFrame::new(punch_pair))]);
                            return Ok(());
                        }
                        _ = tx.recv_punch_done() => {
                            tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Punch success");
                            return Ok(());
                        }
                    }
                }
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Punch failed");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 2. Local Dynamic, Remote Symmetric -> New Interface & Birthday Attack
            // Send PunchMeNow, expect PunchMeNow. After receiving, start collision, expect PunchDone.
            (Dynamic, Symmetric) => {
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Strategy: Local Dynamic, Remote Symmetric, new interface & birthday attack");
                // TODO: Creating a new iface is not strictly necessary; could reuse an available temporary address.
                let (iface, stun_client) = dynamic_iface(&bind_uri).await?;

                let bind_uri = iface.bind_uri();
                punch_ifaces.insert(bind_uri.clone(), iface.clone());
                let outer_addr = stun_client.outer_addr().await?;
                punch_me_now.set_addr(outer_addr);
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Sending PunchMeNow expecting PunchMeNow then collision");
                broker.send_frame([punch_me_now.into()]);

                let link = Link::new(
                    iface.real_addr()?.try_into().expect("Must be SocketAddr"),
                    link.dst(),
                );
                let result: io::Result<()> = loop {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(PUNCH_TIMEOUT_MS))=>
                            break Err(io::Error::new(io::ErrorKind::TimedOut, "Punch timeout")),
                        _ = tx.receive_punch_me_now() =>
                            self.0.collision(&iface, link, punch_pair, KONCK_TTL).await?,
                        _ = tx.recv_punch_done() =>
                            break Ok(()),
                    };
                };
                // If punch failed, clean up the interface
                if result.is_err() {
                    punch_ifaces.remove(&bind_uri);
                    ifaces.unbind(bind_uri).await;
                }
                result
            }
            // 3. Local Symmetric, Remote RestrictedPort -> Birthday Attack
            // Send PunchMeNow, expect PunchMeNow. Use random socket collision, expect PunchDone.
            (Symmetric, RestrictedPort) => {
                // Send PunchMeNow first
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Sending PunchMeNow expecting PunchMeNow then rush");
                broker.send_frame([punch_me_now.into()]);

                if timeout(
                    Duration::from_millis(COLLISION_TIMEOUT_MS),
                    tx.receive_punch_me_now(),
                )
                .await
                .is_ok()
                {
                    // Use new consolidated PortPredictor birthday attack
                    let mut predictor = PortPredictor::new(
                        ifaces.clone(),
                        self.0.iface_factory.clone(),
                        self.0.quic_router.clone(),
                        bind_uri.clone(),
                        link.dst(),
                        BIRTHDAY_ATTACK_PORTS,
                    )?;

                    // Create packet send function
                    let puncher_ref = self.0.clone();
                    let packet_send_fn: PacketSendFn = Arc::new(move |iface, link, ttl, frame| {
                        let puncher = puncher_ref.clone();
                        Box::pin(async move { puncher.send_packet(iface, link, ttl, frame).await })
                    });

                    tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Starting consolidated birthday attack");
                    match predictor
                        .predict(punch_pair, tx.clone(), packet_send_fn)
                        .await
                    {
                        Ok(Some((bind_uri, iface))) => {
                            tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %bind_uri, "Birthday attack succeeded");
                            self.0.punch_ifaces.insert(bind_uri, iface);
                            return Ok(());
                        }
                        Ok(None) => {
                            tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Birthday attack completed without success");
                        }
                        Err(e) => {
                            tracing::warn!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %e, "Birthday attack failed");
                        }
                    }
                }

                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 4. Local Symmetric, Remote RestrictedCone -> Reverse Punching
            // Send PunchMeNow, expect remote to open hole and respond PunchMeNow. Then send direct Konck, expect PunchDone.
            (Symmetric, RestrictedCone) => {
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Strategy: Local Symmetric, Remote RestrictedCone, reverse punching");
                tracing::debug!(target: "punch", %punch_pair, "Sending PunchMeNow expecting PunchMeNow then Konck");
                broker.send_frame([PunchMeNow(punch_me_now)]);
                if timeout(
                    Duration::from_millis(PUNCH_ME_NOW_TIMEOUT_MS),
                    tx.receive_punch_me_now(),
                )
                .await
                .is_err()
                {
                    tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Wait for PunchMeNow timeout, try to connect blindly");
                }

                let iface = ifaces
                    .borrow(&bind_uri)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                for i in 0..5 {
                    tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "Sending Konck expecting PunchDone");
                    self.0
                        .send_packet(&iface, link, KONCK_TTL, Konck(KonckFrame::new(punch_pair)))
                        .await?;
                    let time = Duration::from_millis(KONCK_TIMEOUT_MS);
                    if (timeout(time * (1 << i), tx.recv_punch_done()).await).is_ok() {
                        tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Punch success");
                        return Ok(());
                    }
                }

                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Punch failed");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 5. Local Dynamic
            // New Interface, detect external address. Then send PunchMeNow and Konck, expect PunchDone.
            (Dynamic, _) => {
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Strategy: Local Dynamic, new interface & send PunchMeNow + Konck");
                // Use new iface, update PunchMeNow address.
                // TODO: Creating a new iface is not strictly necessary; could reuse an available temporary address.
                let (iface, stun_client) = dynamic_iface(&bind_uri).await?;
                let outer_addr = stun_client.outer_addr().await?;
                let bind_uri = iface.bind_uri();
                punch_ifaces.insert(bind_uri.clone(), iface.clone());
                punch_me_now.set_addr(outer_addr);
                tracing::debug!(target: "punch", %punch_pair, "Sending PunchMeNow + Konck expecting PunchDone");
                broker.send_frame([PunchMeNow(punch_me_now)]);
                let link = Link::new(
                    iface.real_addr()?.try_into().expect("Must be SocketAddr"),
                    link.dst(),
                );
                let time = Duration::from_millis(100);
                for i in 0..MAX_RETRIES {
                    tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "Sending Konck expecting PunchDone");
                    self.0
                        .send_packet(
                            &iface,
                            link,
                            COLLISION_TTL,
                            Konck(KonckFrame::new(punch_pair)),
                        )
                        .await?;
                    if let Ok((_, _)) = timeout(time * (1 << i), tx.recv_punch_done()).await {
                        tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Punch success");
                        return Ok(());
                    }
                }
                // Punch failed, remove the interface
                punch_ifaces.remove(&bind_uri);
                ifaces.unbind(bind_uri).await;
                Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"))
            }
            // 6. General Punching
            // Send Konck with TTL and PunchMeNow. Expect Konck, then respond PunchDone.
            (FullCone | RestrictedCone, Symmetric)
            | (FullCone | RestrictedCone | RestrictedPort, Dynamic)
            | (_, RestrictedCone | RestrictedPort) => {
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Strategy: General punching, send Konck with TTL & PunchMeNow");
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Sending PunchMeNow + Konck expecting Konck then PunchDone");
                broker.send_frame([PunchMeNow(punch_me_now)]);
                let iface = ifaces
                    .borrow(&bind_uri)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "Sending Konck expecting Konck");
                self.0
                    .send_packet(
                        &iface,
                        link,
                        COLLISION_TTL,
                        Konck(KonckFrame::new(punch_pair)),
                    )
                    .await?;
                let time = Duration::from_millis(PUNCH_TIMEOUT_MS);
                if timeout(time, tx.recv_konck()).await.is_ok() {
                    tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Sending PunchDone");
                    broker.send_frame([PunchDone(PunchDoneFrame::new(punch_pair))]);
                    tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Actively punch success, sent punch done");
                    return Ok(());
                }
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Punch failed");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 7. Local RestrictedPort, Remote Symmetric -> Birthday Attack (Hold Hole)
            // Send packets to 300 random ports, then notify with PunchMeNow. Expect Konck, then respond PunchDone.
            (RestrictedPort, Symmetric) => {
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Strategy: Local RestrictedPort, Remote Symmetric, birthday attack hold hole");
                let iface = ifaces
                    .borrow(&bind_uri)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                self.0
                    .collision(&iface, link, punch_pair, COLLISION_TTL)
                    .await?;
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Sending PunchMeNow expecting Konck then PunchDone");
                broker.send_frame([PunchMeNow(punch_me_now)]);
                let time = PUNCH_TIMEOUT_MS;
                if let Ok((link, ..)) = timeout(Duration::from_millis(time), tx.recv_konck()).await
                {
                    tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "Sending PunchDone");
                    self.0
                        .send_packet(
                            &iface,
                            link,
                            KONCK_TTL,
                            PunchDone(PunchDoneFrame::new(punch_pair)),
                        )
                        .await?;
                    // broker.send_frame([PunchDone(PunchDoneFrame::new(punch_pair))]);
                    tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Punch success with collision");
                    return Ok(());
                }
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 8. Local Symmetric, Remote Dynamic
            // Hold holes on 30 random ports, send PunchMeNow. Expect Collision, then respond PunchMeNow.
            // Repeat until 300 sockets used.
            (Symmetric, Dynamic) => {
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Strategy: Local Symmetric, Remote Dynamic, hold holes & send PunchMeNow");

                // Use new consolidated PortPredictor birthday attack
                let mut predictor = PortPredictor::new(
                    ifaces.clone(),
                    self.0.iface_factory.clone(),
                    self.0.quic_router.clone(),
                    bind_uri.clone(),
                    link.dst(),
                    BIRTHDAY_ATTACK_PORTS,
                )?;
                // Create packet send function
                let puncher_ref = self.0.clone();
                let packet_send_fn: PacketSendFn = Arc::new(move |iface, link, ttl, frame| {
                    let puncher = puncher_ref.clone();
                    Box::pin(async move { puncher.send_packet(iface, link, ttl, frame).await })
                });

                // Send initial PunchMeNow to notify peer
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Sending initial PunchMeNow for Dynamic strategy");
                broker.send_frame([PunchMeNow(punch_me_now)]);

                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Starting consolidated birthday attack for Dynamic strategy");
                match predictor
                    .predict(punch_pair, tx.clone(), packet_send_fn)
                    .await
                {
                    Ok(Some((bind_uri, iface))) => {
                        tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %bind_uri, "Birthday attack succeeded for Dynamic strategy");
                        self.0.punch_ifaces.insert(bind_uri, iface);
                        return Ok(());
                    }
                    Ok(None) => {
                        tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Birthday attack completed without success for Dynamic strategy");
                    }
                    Err(e) => {
                        tracing::warn!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %e, "Birthday attack failed for Dynamic strategy");
                    }
                }
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
        };
        result
    }

    async fn punch_passively(
        &self,
        bind: BindUri,
        local_address: &AddAddressFrame,
        remote_address: &PunchMeNowFrame,
        tx: Arc<Transaction>,
    ) -> io::Result<()> {
        use NatType::*;
        use TraversalFrame::*;
        let remote_nat = remote_address.nat_type();
        let local_nat = local_address.nat_type();
        let punch_pair = Link::new(*local_address.deref(), *remote_address.deref());
        tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Starting passive punch");
        let socket_addr = SocketAddr::try_from(bind.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        if local_nat == Blocked
            || remote_nat == Blocked
            || (local_nat == Symmetric && remote_nat == Symmetric)
        {
            return Err(io::Error::other("Unsupported nat type"));
        }
        let link = Link::new(socket_addr, *remote_address.deref());

        let ifaces = self.0.ifaces.clone();
        let broker = self.0.broker.clone();
        // Note: Receiving PunchMeNow implies we sent an AddAddress frame.
        // For Dynamic NAT, we don't need to create a new interface here;
        // it should have been created before sending AddAddress.
        // 1. Local Dynamic, Remote Symmetric
        // Remote has opened hole. We use new interface to collide, expecting PunchDone.
        // 2. Local RestrictedPort, Remote Symmetric
        // We open holes on 300 random ports, send PunchMeNow. Expect Konck collision, then respond PunchDone.
        // 3. Local Symmetric, Remote RestrictedPort | Dynamic
        // We use random socket collision to open hole, expecting PunchDone.
        // 4. Local RestrictedCone, Remote Symmetric
        // Reflect, konck then Send PunchmeNow, wait for konck, send PunchDone.
        // 5. General Punching
        // Received PunchMeNow implies remote has opened hole. We send direct Konck, expecting PunchDone.

        match (local_nat, remote_nat) {
            // 1. Local Dynamic, Remote Symmetric
            // Remote has opened hole. We use new interface to collide, expecting PunchDone.
            (Dynamic, Symmetric) => {
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Passive strategy: Local Dynamic, Remote Symmetric, use new interface to collide");
                let iface = ifaces
                    .borrow(&bind)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                let time = PUNCH_TIMEOUT_MS;
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(time))=>
                            return Err(io::Error::new(io::ErrorKind::TimedOut, "Punch timeout")),
                        _ = tx.receive_punch_me_now() =>
                            self.0.collision(&iface, link, punch_pair, KONCK_TTL).await?,
                        _ = tx.recv_punch_done() =>
                                return Ok::<(), io::Error>(()),
                    };
                }
            }
            // 2. Local RestrictedPort, Remote Symmetric
            // We open holes on 300 random ports, send PunchMeNow. Expect Konck collision, then respond PunchDone.
            (RestrictedPort, Symmetric) => {
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Passive strategy: Local RestrictedPort, Remote Symmetric, open holes & send PunchMeNow");
                let iface = ifaces
                    .borrow(&bind)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                self.0
                    .collision(&iface, link, punch_pair, COLLISION_TTL)
                    .await?;
                let punch_me_now = PunchMeNowFrame::new(
                    punch_pair,
                    remote_address.paired_with_seq_num(),
                    *local_address.deref(),
                    local_address.tire(),
                    local_nat,
                );
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Sending PunchMeNow expecting Konck then PunchDone");
                broker.send_frame([PunchMeNow(punch_me_now)]);
                let time = PUNCH_TIMEOUT_MS;
                if let Ok((link, _)) =
                    tokio::time::timeout(Duration::from_millis(time), tx.recv_konck()).await
                {
                    tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "Sending punch done");
                    self.0
                        .send_packet(
                            &iface,
                            link,
                            KONCK_TTL,
                            PunchDone(PunchDoneFrame::new(punch_pair)),
                        )
                        .await?;
                    return Ok(());
                }
            }
            // 3. Local Symmetric, Remote RestrictedPort
            // Use new consolidated PortPredictor birthday attack. Expect PunchDone.
            (Symmetric, RestrictedPort | Dynamic) => {
                let mut predictor = PortPredictor::new(
                    ifaces.clone(),
                    self.0.iface_factory.clone(),
                    self.0.quic_router.clone(),
                    bind.clone(),
                    link.dst(),
                    BIRTHDAY_ATTACK_PORTS,
                )?;

                // Create packet send function
                let puncher_ref = self.0.clone();
                let packet_send_fn: PacketSendFn = Arc::new(move |iface, link, ttl, frame| {
                    let puncher = puncher_ref.clone();
                    Box::pin(async move { puncher.send_packet(iface, link, ttl, frame).await })
                });

                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Starting consolidated birthday attack");
                match predictor
                    .predict(punch_pair, tx.clone(), packet_send_fn)
                    .await
                {
                    Ok(Some((bind_uri, iface))) => {
                        tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %bind_uri, "Birthday attack succeeded");
                        self.0.punch_ifaces.insert(bind_uri, iface);
                        return Ok(());
                    }
                    Ok(None) => {
                        tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Birthday attack completed without success");
                    }
                    Err(e) => {
                        tracing::warn!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %e, "Birthday attack failed");
                    }
                }
            }
            // 4. Local RestrictedCone, Remote Symmetric
            // Reflect, Konck and  PunchmeNow, wait for konck, send PunchDone
            (RestrictedCone, Symmetric) => {
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Passive strategy: Local RestrictedCone, Remote Symmetric, reflect & send PunchMeNow");
                let iface = ifaces
                    .borrow(&bind)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                let punch_me_now = PunchMeNowFrame::new(
                    punch_pair,
                    remote_address.paired_with_seq_num(),
                    *local_address.deref(),
                    local_address.tire(),
                    local_nat,
                );
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Sending PunchMeNow expecting Konck then PunchDone");
                let konck_frame = KonckFrame::new(punch_pair);
                self.0
                    .send_packet(&iface, link, COLLISION_TTL, Konck(konck_frame))
                    .await?;
                broker.send_frame([PunchMeNow(punch_me_now)]);
                let time = PUNCH_TIMEOUT_MS;
                if let Ok((link, _)) =
                    tokio::time::timeout(Duration::from_millis(time), tx.recv_konck()).await
                {
                    tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "Sending punch done");
                    self.0
                        .send_packet(
                            &iface,
                            link,
                            KONCK_TTL,
                            PunchDone(PunchDoneFrame::new(punch_pair)),
                        )
                        .await?;
                    return Ok(());
                }
            }
            // 5. General Punching
            // Received PunchMeNow implies remote has opened hole. We send direct Konck, expecting PunchDone.
            _ => {
                tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Passive strategy: General punching, send direct Konck");
                let iface = ifaces
                    .borrow(&bind)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                let time = Duration::from_millis(100);
                for i in 0..MAX_RETRIES {
                    tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "Sending Konck expecting PunchDone");
                    self.0
                        .send_packet(&iface, link, KONCK_TTL, Konck(KonckFrame::new(punch_pair)))
                        .await?;
                    if (timeout(time * (1 << i), tx.recv_punch_done()).await).is_ok() {
                        tracing::debug!(target: "punch", %punch_pair, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "Passively punch success, sending punch done");
                        broker.send_frame([PunchDone(PunchDoneFrame::new(punch_pair))]);
                        return Ok(());
                    }
                }
            }
        };
        Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"))
    }

    fn resolve_punch_connection(
        &self,
        bind: &BindUri,
        local: &SocketEndpointAddr,
        remote: &SocketEndpointAddr,
    ) -> io::Result<(BindUri, Link, PathWay)> {
        if local == remote {
            return Err(io::Error::other("Local and remote endpoints are identical"));
        }

        let (local_addr, remote_addr) = self.extract_addresses(bind, local, remote)?;

        if local_addr.family() != remote_addr.family() {
            return Err(io::Error::other(
                "Local and remote addresses must be in the same address family",
            ));
        }

        let link = Link::new(local_addr, remote_addr);
        let pathway = if matches!(
            (local, remote),
            (
                SocketEndpointAddr::Direct { .. },
                SocketEndpointAddr::Direct { .. }
            )
        ) {
            link.into()
        } else {
            PathWay::new(*local, *remote)
        };

        Ok((bind.clone(), link, pathway))
    }

    fn extract_addresses(
        &self,
        bind: &BindUri,
        local: &SocketEndpointAddr,
        remote: &SocketEndpointAddr,
    ) -> io::Result<(SocketAddr, SocketAddr)> {
        use SocketEndpointAddr::*;
        match (local, remote) {
            (Direct { addr: local_addr }, Direct { addr: remote_addr }) => {
                Ok((*local_addr, *remote_addr))
            }
            (
                Agent { .. },
                Agent {
                    agent: remote_agent,
                    ..
                },
            ) => {
                let iface = InterfaceManager::global().borrow(bind).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Interface not found for bind URI: {:?}", bind),
                    )
                })?;
                let local_real = iface.real_addr()?.try_into().map_err(|_| {
                    io::Error::other("Failed to convert real address to SocketAddr")
                })?;
                Ok((local_real, *remote_agent))
            }
            _ => Err(io::Error::other(
                "Unsupported endpoint type combination for punching",
            )),
        }
    }
}

impl<TX, PH, S> ReceiveFrame<(BindUri, PathWay, Link, TraversalFrame)> for ArcPuncher<TX, PH, S>
where
    TX: SendFrame<TraversalFrame> + Send + Sync + Clone + 'static,
    PH: ProductHeader<OneRttHeader> + Send + Sync + 'static,
    S: PacketSpace<OneRttHeader> + Send + Sync + 'static,
    for<'b> TraversalFrame: Package<S::PacketAssembler<'b>>,
    for<'b> PadTo20: Package<S::PacketAssembler<'b>>,
{
    type Output = ();

    fn recv_frame(
        &self,
        (bind, pathway, link, frame): &(BindUri, PathWay, Link, TraversalFrame),
    ) -> Result<Self::Output, qbase::error::Error> {
        tracing::debug!(target: "punch", %pathway, %link, frame = ?frame, "Received traversal frame");
        match frame {
            TraversalFrame::AddAddress(add_address_frame) => {
                _ = self.recv_add_address_frame(*add_address_frame);
            }
            TraversalFrame::PunchMeNow(punch_me_now_frame) => {
                _ = self.recv_punch_me_now(*pathway, *punch_me_now_frame);
            }
            TraversalFrame::RemoveAddress(remove_address_frame) => {
                self.recv_remove_address_frame(remove_address_frame);
            }
            _ => match self.0.transaction.entry(frame.punch_pair().unwrap().flip()) {
                Entry::Occupied(mut entry) => {
                    let tx = entry.get_mut().1.clone();
                    _ = tx.recv_frame(&(*link, frame.clone()));
                }
                Entry::Vacant(_) => {
                    if matches!(frame, TraversalFrame::Konck(_)) {
                        if let Some(punch_pair) = frame.punch_pair().map(Link::flip) {
                            let link = *link;
                            let puncher = self.clone();
                            let bind = bind.clone();
                            tracing::debug!(target: "punch", %punch_pair, frame = ?frame, %link, "Received unsolicited punch frame, replying directly with PunchDone");
                            tokio::spawn(
                                async move {
                                    match puncher.0.ifaces.borrow(&bind) {
                                        Some(iface) => {
                                            if let Err(error) = puncher
                                                .0
                                                .send_packet(
                                                    &iface,
                                                    link,
                                                    DEFAULT_TTL.try_into().unwrap(),
                                                    TraversalFrame::PunchDone(PunchDoneFrame::new(
                                                        punch_pair,
                                                    )),
                                                )
                                                .await
                                            {
                                                tracing::debug!(target: "punch", %punch_pair, %link, ?error, "Failed to send direct PunchDone for unsolicited frame");
                                            }
                                        }
                                        None => {
                                            tracing::debug!(target: "punch", %punch_pair, %link, "Interface not found for bind uri: {}", bind);
                                        }
                                    }
                                }
                                .instrument_in_current()
                                .in_current_span(),
                            );
                        }
                    } else {
                        tracing::debug!(target: "punch", frame = ?frame, "Received unexpected frame");
                    }
                }
            },
        };

        Ok(())
    }
}

#[inline]
async fn dynamic_iface(
    bind_uri: &BindUri,
    ifaces: &Arc<InterfaceManager>,
    iface_factory: &Arc<dyn ProductIO>,
    quic_router: &Arc<QuicRouter>,
    stun_servers: &[SocketAddr],
) -> io::Result<(Interface, StunClient)> {
    const MIN_PORT: u16 = 1024;
    const MAX_PORT: u16 = u16::MAX;
    let (ip_family, device, _port) = bind_uri.as_iface_bind_uri().ok_or_else(|| {
        let error = "Invalid bind uri, expected bind uri with iface schema";
        io::Error::new(io::ErrorKind::InvalidInput, error)
    })?;
    let port = rand::random::<u16>() % (MAX_PORT - MIN_PORT) + MIN_PORT;
    let bind_uri = format!(
        "iface://{ip_family}.{device}:{port}?{}=true",
        BindUri::TEMPORARY_PROP
    );
    let bind_uri = BindUri::from_str(bind_uri.as_str())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    ifaces
        .bind(bind_uri, iface_factory.clone())
        .await
        .with_components_mut(|components, iface| {
            // Ensure this temporary iface can receive+deliver QUIC packets to the connection.
            // Must use the connection-owned router.
            components.init_with(|| QuicRouterComponent::new(quic_router.clone()));

            let local_addr = SocketAddr::try_from(iface.real_addr()?).map_err(io::Error::other)?;
            let stun_server = *stun_servers
                .iter()
                .find(|addr| addr.is_ipv4() == local_addr.is_ipv4())
                .ok_or_else(|| io::Error::other("No STUN server matches local address family"))?;
            let stun_router = components
                .init_with(|| {
                    let ref_iface = iface.downgrade();
                    StunRouterComponent::new(ref_iface)
                })
                .router();
            let stun_client = components
                .init_with(|| {
                    let client =
                        StunClient::new(iface.downgrade(), stun_router.clone(), stun_server, None);
                    StunClientComponent::new(client)
                })
                .client();
            components.init_with(|| {
                ReceiveAndDeliverPacket::builder(iface.downgrade())
                    .quic_router(quic_router.clone())
                    .stun_router(stun_router)
                    .init()
            });
            Ok((iface.to_owned(), stun_client))
        })
}
