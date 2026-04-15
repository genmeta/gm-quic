use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::poll_fn,
    io,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use qbase::{frame::PunchHelloFrame, net::addr::BoundAddr};
use qinterface::{
    Interface,
    bind_uri::{BindUri, BindUriScheme},
    component::route::{QuicRouter, QuicRouterComponent},
    io::{IO, ProductIO},
    manager::InterfaceManager,
};

use crate::{
    Link,
    punch::{
        scheduler::SCHEDULER,
        tx::{PunchId, Transaction},
    },
    route::ReceiveAndDeliverPacket,
};

const MAX_CONCURRENT_SOCKETS: usize = 60;
const INTERFACES_PER_ROUND: usize = 30;
const MIN_PORT: u16 = 1024;
const PACKET_TTL: u8 = 64;
const FIRST_PROBE_ID: u32 = 1;
const MAX_PROBES: u32 = 300;
const GENERATION_WAIT: Duration = Duration::from_millis(500);

pub struct PortPredictor {
    ifaces: Arc<InterfaceManager>,
    factory: Arc<dyn ProductIO>,
    quic_router: Arc<QuicRouter>,
    bind_uri: BindUri,
    dst: SocketAddr,
    device: String,
    probes: ProbeTable,
    quota_held: u32,
    probes_created: u32,
    generation: u32,
}

#[derive(Debug)]
struct PendingProbe {
    bind_uri: BindUri,
    iface: Interface,
    port: u16,
    generation: u32,
}

pub type PacketSendFn = Arc<
    dyn Fn(
            &Interface,
            Link,
            u8,
            PunchHelloFrame,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + '_>>
        + Send
        + Sync,
>;

struct ProbeTable {
    pending: HashMap<u32, PendingProbe>,
    active_ports: HashMap<u16, u32>,
    generations: BTreeMap<u32, BTreeSet<u32>>,
    next_probe_id: u32,
}

impl ProbeTable {
    fn new() -> Self {
        Self {
            pending: HashMap::new(),
            active_ports: HashMap::new(),
            generations: BTreeMap::new(),
            next_probe_id: FIRST_PROBE_ID,
        }
    }

    fn len(&self) -> usize {
        self.pending.len()
    }

    fn contains_port(&self, port: u16) -> bool {
        self.active_ports.contains_key(&port)
    }

    fn allocate_probe_id(&mut self) -> u32 {
        let probe_id = self.next_probe_id;
        self.next_probe_id = self.next_probe_id.wrapping_add(1);
        if self.next_probe_id < FIRST_PROBE_ID {
            self.next_probe_id = FIRST_PROBE_ID;
        }
        probe_id
    }

    fn insert(
        &mut self,
        probe_id: u32,
        bind_uri: BindUri,
        iface: Interface,
        port: u16,
        generation: u32,
    ) {
        self.active_ports.insert(port, probe_id);
        self.generations
            .entry(generation)
            .or_default()
            .insert(probe_id);
        self.pending.insert(
            probe_id,
            PendingProbe {
                bind_uri,
                iface,
                port,
                generation,
            },
        );
    }

    fn take(&mut self, probe_id: u32) -> Option<PendingProbe> {
        let probe = self.pending.remove(&probe_id)?;
        self.active_ports.remove(&probe.port);
        if let Some(probe_ids) = self.generations.get_mut(&probe.generation) {
            probe_ids.remove(&probe_id);
            if probe_ids.is_empty() {
                self.generations.remove(&probe.generation);
            }
        }
        Some(probe)
    }

    fn oldest_generation_id(&self) -> Option<u32> {
        self.generations
            .first_key_value()
            .map(|(generation, _)| *generation)
    }

    fn generation_probe_ids(&self, generation: u32) -> Vec<u32> {
        self.generations
            .get(&generation)
            .map(|probe_ids| probe_ids.iter().copied().collect())
            .unwrap_or_default()
    }

    fn pending_probe_ids(&self) -> Vec<u32> {
        self.pending.keys().copied().collect()
    }

    fn drain_bind_uris(&mut self) -> Vec<BindUri> {
        self.active_ports.clear();
        self.generations.clear();
        self.pending
            .drain()
            .map(|(_, probe)| probe.bind_uri)
            .collect()
    }
}

impl PortPredictor {
    pub fn new(
        ifaces: Arc<InterfaceManager>,
        factory: Arc<dyn ProductIO>,
        quic_router: Arc<QuicRouter>,
        bind_uri: BindUri,
        dst: SocketAddr,
    ) -> io::Result<Self> {
        let device = match bind_uri.scheme() {
            BindUriScheme::Iface => bind_uri.as_iface_bind_uri().unwrap().1.to_string(),
            BindUriScheme::Inet => bind_uri.as_inet_bind_uri().unwrap().ip().to_string(),
            _ => return Err(io::ErrorKind::Unsupported.into()),
        };
        tracing::debug!(
            target: "punch",
            bind_uri = %bind_uri,
            dst = %dst,
            device = %device,
            "Created port predictor"
        );
        Ok(Self {
            ifaces,
            factory,
            quic_router,
            bind_uri,
            dst,
            device,
            probes: ProbeTable::new(),
            quota_held: 0,
            probes_created: 0,
            generation: 0,
        })
    }

    fn release_quota(&mut self, count: u32) -> io::Result<()> {
        SCHEDULER
            .lock()
            .unwrap()
            .release_port(count, self.dst, self.device.clone())?;
        self.quota_held = self.quota_held.saturating_sub(count);
        Ok(())
    }

    fn port_to_bind_uri(&self, port: u16) -> BindUri {
        match self.bind_uri.scheme() {
            BindUriScheme::Iface => {
                let (ip_family, device, _) = self.bind_uri.as_iface_bind_uri().unwrap();
                let bind_uri = format!(
                    "iface://{ip_family}.{device}:{port}?{}=true",
                    BindUri::TEMPORARY_PROP
                );
                BindUri::from_str(bind_uri.as_str()).unwrap_or_else(|e| {
                    panic!("Constructed invalid iface bind URI {bind_uri}: {e}")
                })
            }
            BindUriScheme::Inet => {
                let socket_addr = self.bind_uri.as_inet_bind_uri().unwrap();
                let ip = socket_addr.ip();
                let bind_uri = format!("inet://{ip}:{port}?{}=true", BindUri::TEMPORARY_PROP);
                BindUri::from_str(bind_uri.as_str())
                    .unwrap_or_else(|e| panic!("Constructed invalid inet bind URI {bind_uri}: {e}"))
            }
            _ => unreachable!("Unsupported bind URI scheme for port prediction"),
        }
    }

    async fn release_interface(&mut self, bind_uri: BindUri) {
        self.ifaces.unbind(bind_uri).await;
        if let Err(error) = self.release_quota(1) {
            tracing::warn!(target: "punch", %error, "Failed to release quota for interface");
        }
    }

    async fn release_probe(&mut self, probe_id: u32) -> bool {
        let Some(probe) = self.probes.take(probe_id) else {
            return false;
        };
        self.release_interface(probe.bind_uri).await;
        true
    }

    fn drain_and_claim(&mut self, tx: &Transaction) -> io::Result<Option<(BindUri, Interface)>> {
        while let Some((link, frame)) = tx.try_next_punch_done() {
            let probe_id = frame.probe_id();
            tracing::debug!(target: "punch", %link, probe_id, "Punch done received");
            if let Some(result) = self.claim_probe(probe_id) {
                if let Err(error) = self.release_quota(1) {
                    tracing::warn!(target: "punch", %error, "Failed to release quota for claimed probe");
                }
                return Ok(Some(result));
            }
            tracing::debug!(target: "punch", %link, probe_id, "Ignoring punch done for inactive probe");
        }
        Ok(None)
    }

    async fn evict_for_capacity(&mut self, incoming: usize) -> io::Result<()> {
        while self.probes.len().saturating_add(incoming) > MAX_CONCURRENT_SOCKETS {
            let Some(generation) = self.probes.oldest_generation_id() else {
                break;
            };
            let probe_ids = self.probes.generation_probe_ids(generation);
            let mut released = 0;
            for probe_id in probe_ids {
                if self.release_probe(probe_id).await {
                    released += 1;
                }
            }
            tracing::debug!(target: "punch", generation, released, active_probes = self.probes.len(), "Evicted oldest generation");
        }
        Ok(())
    }

    fn claim_probe(&mut self, probe_id: u32) -> Option<(BindUri, Interface)> {
        let probe = self.probes.take(probe_id)?;
        Some((probe.bind_uri, probe.iface))
    }

    async fn finalize(
        &mut self,
        result: (BindUri, Interface),
    ) -> io::Result<Option<(BindUri, Interface)>> {
        if let Err(error) = self.release_all().await {
            tracing::warn!(target: "punch", %error, "Failed to cleanup remaining probes after success");
        }
        Ok(Some(result))
    }

    pub(super) async fn predict(
        &mut self,
        punch_id: PunchId,
        tx: Arc<Transaction>,
        packet_send_fn: PacketSendFn,
    ) -> io::Result<Option<(BindUri, Interface)>> {
        tracing::debug!(target: "punch", %punch_id, "Starting port prediction");
        let mut consecutive_empty = 0u32;

        while self.probes_created < MAX_PROBES {
            // CHECK: drain all arrived PunchDone before doing more work
            if let Some(result) = self.drain_and_claim(tx.as_ref())? {
                return self.finalize(result).await;
            }

            // ACT: scatter a generation of probes (pure producer, no early exit)
            match self.scatter_probes(punch_id, &packet_send_fn).await {
                Ok(0) => {
                    consecutive_empty += 1;
                    if consecutive_empty >= 3 {
                        tracing::warn!(target: "punch", %punch_id, "3 consecutive empty scatter rounds, aborting");
                        break;
                    }
                }
                Ok(_) => consecutive_empty = 0,
                Err(error) => {
                    tracing::warn!(target: "punch", %punch_id, %error, "Failed to scatter probes, aborting");
                    break;
                }
            }

            // WAIT: give the current generation time to receive PunchDone
            if let Ok((link, frame)) =
                tokio::time::timeout(GENERATION_WAIT, tx.next_punch_done()).await
            {
                let probe_id = frame.probe_id();
                tracing::debug!(target: "punch", %link, probe_id, "Punch done received during wait");
                if let Some(result) = self.claim_probe(probe_id) {
                    if let Err(error) = self.release_quota(1) {
                        tracing::warn!(target: "punch", %error, "Failed to release quota for claimed probe");
                    }
                    return self.finalize(result).await;
                }
                tracing::debug!(target: "punch", %link, probe_id, "Ignoring punch done for inactive probe during wait");
            }
        }

        // Final drain before giving up
        if let Some(result) = self.drain_and_claim(tx.as_ref())? {
            return self.finalize(result).await;
        }

        if let Err(e) = self.release_all().await {
            tracing::error!(target: "punch", %punch_id, %e, "Failed to cleanup resources");
        }
        tracing::debug!(target: "punch", %punch_id, probes_created = self.probes_created, "Port prediction finished without match");
        Ok(None)
    }

    async fn scatter_probes(
        &mut self,
        punch_id: PunchId,
        packet_send_fn: &PacketSendFn,
    ) -> io::Result<usize> {
        let granted = self.acquire_quota(INTERFACES_PER_ROUND as u32).await? as usize;
        tracing::debug!(target: "punch", %punch_id, granted, "Batch quota acquired");

        self.evict_for_capacity(granted).await?;

        let generation = self.generation;
        self.generation += 1;
        self.probes_created += granted as u32;
        tracing::debug!(target: "punch", %punch_id, generation, granted, "Scattering probe generation");

        // Create interfaces
        let mut pending_probes = Vec::with_capacity(granted);
        for _ in 0..granted {
            let (bind_uri, iface) = match self.create_interface().await {
                Ok(result) => result,
                Err(_) => {
                    if let Err(error) = self.release_quota(1) {
                        tracing::warn!(target: "punch", %error, "Failed to release unused quota");
                    }
                    continue;
                }
            };
            let Ok(BoundAddr::Internet(socket_addr)) = iface.bound_addr() else {
                self.release_interface(bind_uri).await;
                continue;
            };
            let port = socket_addr.port();
            let probe_id = self.probes.allocate_probe_id();
            let link = Link::new(socket_addr, self.dst);
            let frame = PunchHelloFrame::new(punch_id.local_seq, punch_id.remote_seq, probe_id);
            pending_probes.push((probe_id, bind_uri, iface, port, link, frame));
        }

        if pending_probes.is_empty() {
            return Ok(0);
        }

        // Send probes and register results
        let mut successful_sends = 0;
        for (probe_id, bind_uri, iface, port, link, frame) in pending_probes {
            if packet_send_fn(&iface, link, PACKET_TTL, frame)
                .await
                .is_ok()
            {
                self.probes
                    .insert(probe_id, bind_uri, iface, port, generation);
                successful_sends += 1;
            } else {
                self.release_interface(bind_uri).await;
            }
        }

        tracing::debug!(target: "punch", %punch_id, generation, successful_sends, "Probes scattered");
        Ok(successful_sends)
    }

    async fn create_interface(&mut self) -> io::Result<(BindUri, Interface)> {
        for _ in 0..10 {
            let port = rand::random::<u16>() % (u16::MAX - MIN_PORT) + MIN_PORT;
            if self.probes.contains_port(port) {
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
                    return Ok((bind_addr, iface));
                }
                Err(_) => {
                    self.ifaces.unbind(bind_addr).await;
                    continue;
                }
            }
        }
        tracing::warn!(target: "punch", bind_uri = %self.bind_uri, dst = %self.dst, "Failed to create interface after 10 attempts");
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "Failed to bind port after max retries",
        ))
    }

    async fn release_all(&mut self) -> io::Result<()> {
        tracing::debug!(target: "punch", active_probes = self.probes.len(), 
                      "Starting resource cleanup");
        let probe_ids = self.probes.pending_probe_ids();
        for probe_id in probe_ids {
            self.release_probe(probe_id).await;
        }
        if self.quota_held > 0 {
            let orphaned = self.quota_held;
            tracing::warn!(target: "punch", orphaned, "Releasing orphaned quota without pending probes");
            self.release_quota(orphaned)?;
        }
        tracing::debug!(target: "punch", "Resource cleanup completed");
        Ok(())
    }

    async fn acquire_quota(&mut self, count: u32) -> io::Result<u32> {
        let count = count.min(MAX_PROBES - self.probes_created);
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!("Would exceed maximum limit of {}", MAX_PROBES),
            ));
        }
        let granted = poll_fn(|cx| {
            SCHEDULER
                .lock()
                .unwrap()
                .poll_allocate(cx, self.dst, self.device.clone(), count)
        })
        .await?;
        self.quota_held += granted;
        Ok(granted)
    }
}

impl Drop for PortPredictor {
    fn drop(&mut self) {
        let quota_held = self.quota_held;
        self.quota_held = 0;
        if quota_held > 0
            && let Err(error) =
                SCHEDULER
                    .lock()
                    .unwrap()
                    .release_port(quota_held, self.dst, self.device.clone())
        {
            tracing::warn!(target: "punch", %error, quota_held, "Failed to release predictor quota during drop");
        }

        let bind_uris = self.probes.drain_bind_uris();
        let futures: Vec<_> = bind_uris
            .into_iter()
            .map(|bind_uri| self.ifaces.unbind(bind_uri))
            .collect();
        if !futures.is_empty() {
            tokio::spawn(async move {
                futures::future::join_all(futures).await;
            });
        }
    }
}
