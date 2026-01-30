use std::{
    collections::{BTreeMap, HashMap},
    future::poll_fn,
    io,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use qinterface::{
    Interface,
    bind_uri::{BindUri, BindUriSchema},
    component::route::{QuicRouter, QuicRouterComponent},
    io::{IO, ProductIO},
    manager::InterfaceManager,
};

use crate::{
    Link,
    frame::{TraversalFrame, konck::KonckFrame},
    punch::{scheduler::SCHEDULER, tx::Transaction},
    route::ReceiveAndDeliverPacket,
};

const PUNCH_INITIAL_RTT: Duration = Duration::from_millis(333);
const RTT_MULTIPLIER: u32 = 3;
const MAX_CONCURRENT_SOCKETS: usize = 60;
const INTERFACES_PER_ROUND: usize = 30;
const MAX_ROUNDS: i32 = 10;
const RESPONSE_TIMEOUT_MS: u64 = 100;
const MIN_PORT: u16 = 1024;
const PACKET_TTL: u8 = 64;

pub type PacketSendFn = Arc<
    dyn Fn(
            &Interface,
            Link,
            u8,
            TraversalFrame,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + '_>>
        + Send
        + Sync,
>;

pub struct PortPredictor {
    ifaces: Arc<InterfaceManager>,
    factory: Arc<dyn ProductIO>,
    quic_router: Arc<QuicRouter>,
    port_map: HashMap<u16, (BindUri, Interface, tokio::time::Instant)>,
    eviction_order: BTreeMap<tokio::time::Instant, u16>,
    bind_uri: BindUri,
    dst: SocketAddr,
    estimated_rtt: Duration,
    total_created: u32,
    max_total: u32,
    interface_name: String,
}

impl PortPredictor {
    pub fn new(
        ifaces: Arc<InterfaceManager>,
        factory: Arc<dyn ProductIO>,
        quic_router: Arc<QuicRouter>,
        bind_uri: BindUri,
        dst: SocketAddr,
        max_total: u32,
    ) -> io::Result<Self> {
        let interface_name = match bind_uri.scheme() {
            BindUriSchema::Iface => bind_uri.as_iface_bind_uri().unwrap().1.to_string(),
            BindUriSchema::Inet => bind_uri.as_inet_bind_uri().unwrap().ip().to_string(),
            _ => return Err(io::ErrorKind::Unsupported.into()),
        };
        tracing::debug!(target: "punch", %bind_uri, %dst, max_total, %interface_name, "Created port predictor");
        Ok(Self {
            ifaces,
            factory,
            quic_router,
            port_map: HashMap::new(),
            eviction_order: BTreeMap::new(),
            bind_uri,
            dst,
            estimated_rtt: PUNCH_INITIAL_RTT,
            total_created: 0,
            max_total,
            interface_name,
        })
    }

    fn port_to_bind_uri(&self, port: u16) -> BindUri {
        match self.bind_uri.scheme() {
            BindUriSchema::Iface => {
                let (ip_family, device, _) = self.bind_uri.as_iface_bind_uri().unwrap();
                let bind_uri = format!(
                    "iface://{ip_family}.{device}:{port}?{}=true",
                    BindUri::TEMPORARY_PROP
                );
                BindUri::from_str(bind_uri.as_str()).unwrap_or_else(|e| {
                    panic!("Constructed invalid iface bind URI {bind_uri}: {e}",)
                })
            }
            BindUriSchema::Inet => {
                let socket_addr = self.bind_uri.as_inet_bind_uri().unwrap();
                let ip = socket_addr.ip();
                let bind_uri = format!("inet://{ip}:{port}?{}=true", BindUri::TEMPORARY_PROP);
                BindUri::from_str(bind_uri.as_str()).unwrap_or_else(|e| {
                    panic!("Constructed invalid inet bind URI {bind_uri}: {e}",)
                })
            }
            _ => unreachable!("Unsupported bind URI schema for port prediction"),
        }
    }

    async fn recycle_expired_interfaces(&mut self) -> io::Result<usize> {
        let timeout = self.estimated_rtt * RTT_MULTIPLIER;
        let now = tokio::time::Instant::now();
        let mut recycled = 0;
        let cutoff = now - timeout;
        // Collect expired instants to avoid modifying while iterating
        let expired_instants: Vec<_> = self
            .eviction_order
            .range(..=cutoff)
            .map(|(&instant, &port)| (instant, port))
            .collect();
        for (instant, port) in expired_instants {
            if let Some((bind_uri, _iface, _)) = self.port_map.remove(&port) {
                self.eviction_order.remove(&instant);
                self.ifaces.unbind(bind_uri).await;
                if let Err(e) = self.release_quota() {
                    tracing::warn!(target: "punch", %e, port, "Failed to release quota for interface");
                }
                recycled += 1;
            }
        }
        if recycled > 0 {
            tracing::debug!(target: "punch", recycled, active_ports = self.port_map.len(), 
                          timeout_ms = timeout.as_millis(), "Recycled expired ports");
        }
        Ok(recycled)
    }

    async fn recycle_if_full(&mut self) -> io::Result<()> {
        while self.port_map.len() >= MAX_CONCURRENT_SOCKETS {
            if let Some((&instant, &port)) = self.eviction_order.first_key_value() {
                if let Some((bind_uri, _iface, _)) = self.port_map.remove(&port) {
                    self.eviction_order.remove(&instant);
                    self.ifaces.unbind(bind_uri).await;
                    if let Err(e) = self.release_quota() {
                        tracing::warn!(target: "punch", %e, port, "Failed to release quota for interface");
                    }
                } else {
                    // Should not happen
                    self.eviction_order.remove(&instant);
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    async fn claim_interface(&mut self, src_port: u16) -> Option<(BindUri, Interface)> {
        if let Some((bind_uri, iface, instant)) = self.port_map.remove(&src_port) {
            self.eviction_order.remove(&instant);
            return Some((bind_uri, iface));
        }
        None
    }

    pub async fn predict(
        &mut self,
        punch_pair: Link,
        tx: Arc<Transaction>,
        packet_send_fn: PacketSendFn,
    ) -> io::Result<Option<(BindUri, Interface)>> {
        tracing::debug!(target: "punch", %punch_pair, "Starting port prediction");
        let interfaces_per_round = INTERFACES_PER_ROUND;
        let max_rounds = MAX_ROUNDS;
        let response_timeout = Duration::from_millis(RESPONSE_TIMEOUT_MS);
        let mut rounds_processed = 0;
        let mut last_error = None;
        while rounds_processed < max_rounds && self.total_created < self.max_total {
            // Allocate and probe interfaces
            if self
                .allocate_and_probe(punch_pair, &packet_send_fn, interfaces_per_round)
                .await
                .is_ok()
            {
                // Wait for punch done response (could be from previous rounds or current round)
                if let Ok((link, _)) =
                    tokio::time::timeout(response_timeout, tx.recv_punch_done()).await
                {
                    tracing::debug!(target: "punch", %punch_pair, %link, "Punch done received");
                    let result = self.claim_interface(link.src().port()).await;
                    if result.is_none() {
                        tracing::warn!(target: "punch", %link, "Could not find interface for punch done");
                    }
                    self.cleanup_all_resources().await?;
                    return Ok(result);
                }
            } else {
                last_error = Some(io::Error::other(format!(
                    "Failed to process round {}",
                    rounds_processed
                )));
            }
            rounds_processed += 1;
        }

        // Cleanup and return
        if let Err(e) = self.cleanup_all_resources().await {
            tracing::error!(target: "punch", %punch_pair, %e, "Failed to cleanup resources after port prediction");
        }
        tracing::debug!(target: "punch", %punch_pair, rounds_processed, "Port prediction failed after maximum rounds");
        last_error.map_or(Ok(None), Err)
    }

    async fn allocate_and_probe(
        &mut self,
        punch_pair: Link,
        packet_send_fn: &PacketSendFn,
        interfaces_count: usize,
    ) -> io::Result<Vec<Interface>> {
        // Recycle expired and over-limit interfaces before allocating new ones
        self.recycle_expired_interfaces().await?;
        self.recycle_if_full().await?;

        let interfaces_count = interfaces_count.min((self.max_total - self.total_created) as usize);
        tracing::debug!(target: "punch", %punch_pair, interfaces_count, "Allocating interfaces");

        let mut interfaces = Vec::new();
        for _i in 0..interfaces_count {
            match self.create_single_interface().await {
                Ok((bind_uri, iface)) => {
                    if let Ok(qbase::net::addr::BoundAddr::Internet(socket_addr)) =
                        iface.bound_addr()
                    {
                        let port = socket_addr.port();
                        let now = tokio::time::Instant::now();
                        self.port_map.insert(port, (bind_uri, iface.clone(), now));
                        self.eviction_order.insert(now, port);
                        interfaces.push(iface);
                    }
                }
                Err(_e) => {}
            }
        }

        if interfaces.is_empty() {
            tracing::error!(target: "punch", %punch_pair, interfaces_count, "Failed to create any interfaces");
            return Err(io::Error::other("Failed to create any interfaces"));
        }

        self.send_probe_packets(&interfaces, punch_pair, packet_send_fn)
            .await
    }

    async fn create_single_interface(&mut self) -> io::Result<(BindUri, Interface)> {
        self.acquire_quota().await?;
        loop {
            let port = rand::random::<u16>() % (u16::MAX - MIN_PORT) + MIN_PORT;
            if self.port_map.contains_key(&port) {
                continue;
            }
            let bind_addr = self.port_to_bind_uri(port);
            let bind_iface = self
                .ifaces
                .bind(bind_addr.clone(), self.factory.clone())
                .await;

            bind_iface.with_components_mut(|components, iface| {
                components.init_with(|| QuicRouterComponent::new(self.quic_router.clone()));
                components.init_with(|| {
                    ReceiveAndDeliverPacket::builder(iface.downgrade())
                        .quic_router(self.quic_router.clone())
                        .init()
                });
            });

            let iface = bind_iface.borrow();

            match iface.bound_addr() {
                Ok(_bound_addr) => {
                    self.total_created += 1;
                    return Ok((bind_addr, iface));
                }
                Err(_) => {
                    if let Err(e) = self.release_quota() {
                        tracing::warn!(target: "punch", %e, "Failed to release quota after interface creation failure");
                    }
                    continue;
                }
            }
        }
    }

    async fn send_probe_packets(
        &mut self,
        interfaces: &[Interface],
        punch_pair: Link,
        packet_send_fn: &PacketSendFn,
    ) -> io::Result<Vec<Interface>> {
        tracing::debug!(target: "punch", %punch_pair, interface_count = interfaces.len(), "Sending packets");
        let mut successful_sends = 0;
        let mut successful_interfaces = Vec::new();
        for iface in interfaces {
            if let Ok(qbase::net::addr::BoundAddr::Internet(socket_addr)) = iface.bound_addr() {
                let link = Link::new(socket_addr, punch_pair.dst());
                let frame = TraversalFrame::Konck(KonckFrame::new(punch_pair));
                if packet_send_fn(iface, link, PACKET_TTL, frame).await.is_ok() {
                    successful_sends += 1;
                    successful_interfaces.push(iface.clone());
                } else {
                    // Clean up failed interface immediately
                    let port = socket_addr.port();
                    if let Some((bind_uri, _, instant)) = self.port_map.remove(&port) {
                        self.eviction_order.remove(&instant);
                        self.ifaces.unbind(bind_uri).await;
                        if let Err(cleanup_err) = self.release_quota() {
                            tracing::warn!(target: "punch", %cleanup_err, port, "Failed to cleanup port after packet send failure");
                        }
                    }
                }
            }
        }
        tracing::debug!(target: "punch", %punch_pair, successful_sends, 
                      failed_sends = interfaces.len() - successful_sends,
                      total_interfaces = interfaces.len(), "Packet sending completed");
        if successful_sends > 0 || interfaces.is_empty() {
            Ok(successful_interfaces)
        } else {
            Err(io::Error::other(format!(
                "Failed to send packets to all {} interfaces",
                interfaces.len()
            )))
        }
    }

    async fn cleanup_all_resources(&mut self) -> io::Result<()> {
        tracing::debug!(target: "punch", active_ports = self.port_map.len(), 
                      "Starting resource cleanup");
        let ports_to_cleanup: Vec<_> = self.port_map.keys().cloned().collect();
        for port in ports_to_cleanup {
            if let Some((bind_uri, _, instant)) = self.port_map.remove(&port) {
                self.eviction_order.remove(&instant);
                self.ifaces.unbind(bind_uri).await;
                if let Err(e) = self.release_quota() {
                    tracing::warn!(target: "punch", %e, port, "Failed to release quota for interface");
                }
            }
        }
        tracing::debug!(target: "punch", "Resource cleanup completed");
        Ok(())
    }

    fn release_quota(&mut self) -> io::Result<()> {
        SCHEDULER
            .lock()
            .unwrap()
            .release_port(1, self.dst, self.interface_name.clone())
            .map_err(|e| {
                tracing::warn!(target: "punch", %e, "Failed to release 1 quota unit to scheduler");
                e
            })?;
        Ok(())
    }

    async fn acquire_quota(&mut self) -> io::Result<()> {
        if self.total_created + 1 > self.max_total {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!(
                    "Requested 1 port would exceed maximum limit of {}",
                    self.max_total
                ),
            ));
        }
        let allocated = poll_fn(|cx| {
            SCHEDULER.lock().unwrap().poll_port_allocation(
                cx,
                self.dst,
                self.interface_name.clone(),
                1,
            )
        })
        .await?;
        if allocated != 1 {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!("Expected to allocate 1 quota unit, but got {}", allocated),
            ));
        }
        Ok(())
    }
}

impl Drop for PortPredictor {
    fn drop(&mut self) {
        let futures: Vec<_> = self
            .port_map
            .values()
            .map(|(bind_uri, _, _)| self.ifaces.unbind(bind_uri.clone()))
            .collect();
        if !futures.is_empty() {
            tokio::spawn(async move {
                futures::future::join_all(futures).await;
            });
        }
    }
}
