use std::{
    collections::VecDeque, future::poll_fn, io, net::SocketAddr, str::FromStr, sync::Arc,
    time::Duration,
};

use qinterface::{
    Interface,
    factory::ProductQuicIO,
    logical::{BindUri, BindUriSchema, QuicInterface, QuicInterfaces},
};

use crate::{
    Link,
    frame::{TraversalFrame, konck::KonckFrame},
    punch::{scheduler::SCHEDULER, tx::Transaction},
};

const PUNCH_INITIAL_RTT: Duration = Duration::from_millis(333);
const RTT_MULTIPLIER: u32 = 3;
const MAX_CONCURRENT_SOCKETS: usize = 60;

pub type PacketSendFn = Arc<
    dyn Fn(
            &QuicInterface,
            Link,
            u8,
            TraversalFrame,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + '_>>
        + Send
        + Sync,
>;

pub struct PortPredictor {
    ifaces: Arc<QuicInterfaces>,
    factory: Arc<dyn ProductQuicIO>,
    ports: VecDeque<(u16, BindUri, QuicInterface, tokio::time::Instant)>,
    bind_uri: BindUri,
    dst: SocketAddr,
    estimated_rtt: Duration,
    total_created: usize,
    max_total: u32,
    interface_name: String,
}

impl PortPredictor {
    pub fn new(
        ifaces: Arc<QuicInterfaces>,
        factory: Arc<dyn ProductQuicIO>,
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
            ports: VecDeque::new(),
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
        let mut i = 0;
        while i < self.ports.len() {
            if now.duration_since(self.ports[i].3) >= timeout {
                let (port, bind_uri, _iface, _) = self.ports.remove(i).unwrap();
                self.ifaces.unbind(bind_uri).await;
                if let Err(e) = self.release_quota() {
                    tracing::warn!(target: "punch", %e, port, "Failed to release quota for interface");
                }
                recycled += 1;
            } else {
                i += 1;
            }
        }
        if recycled > 0 {
            tracing::debug!(target: "punch", recycled, active_ports = self.ports.len(), 
                          timeout_ms = timeout.as_millis(), "Recycled expired ports");
        }
        Ok(recycled)
    }

    async fn recycle_if_full(&mut self) -> io::Result<()> {
        while self.ports.len() >= MAX_CONCURRENT_SOCKETS {
            if let Some((port, bind_uri, _iface, _)) = self.ports.pop_front() {
                self.ifaces.unbind(bind_uri).await;
                if let Err(e) = self.release_quota() {
                    tracing::warn!(target: "punch", %e, port, "Failed to release quota for interface");
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    async fn handle_punch_done(&mut self, src_port: u16) -> Option<(BindUri, QuicInterface)> {
        let mut i = 0;
        while i < self.ports.len() {
            if self.ports[i].0 == src_port {
                let (_port, bind_uri, iface, _) = self.ports.remove(i).unwrap();
                return Some((bind_uri, iface));
            }
            i += 1;
        }
        None
    }

    pub async fn predict(
        &mut self,
        punch_pair: Link,
        tx: Arc<Transaction>,
        packet_send_fn: PacketSendFn,
    ) -> io::Result<Option<(BindUri, QuicInterface)>> {
        tracing::debug!(target: "punch", %punch_pair, "Starting port prediction");
        let interfaces_per_round = 30;
        let max_rounds = 10;
        let response_timeout = Duration::from_millis(100);
        let mut rounds_processed = 0;
        let mut last_error = None;
        while rounds_processed < max_rounds && ((self.total_created as u32) < self.max_total) {
            if let Some((link, _)) = tx.try_punch_done()
                && let Some(result) = self.handle_punch_done(link.src().port()).await
            {
                tracing::debug!(target: "punch", %punch_pair, "Early punch done detected");
                return Ok(Some(result));
            }
            match self
                .allocate_and_probe(punch_pair, &packet_send_fn, interfaces_per_round)
                .await
            {
                Ok(_) => {
                    if let Ok((link, _)) =
                        tokio::time::timeout(response_timeout, tx.recv_punch_done()).await
                    {
                        tracing::debug!(target: "punch", %punch_pair, %link, "Punch done received after round");
                        if let Some(result) = self.handle_punch_done(link.src().port()).await {
                            return Ok(Some(result));
                        }
                        tracing::warn!(target: "punch", %link, "Could not find interface for punch done");
                        return Ok(None);
                    }
                }
                Err(_) => {
                    last_error = Some(io::Error::other(format!(
                        "Failed to process round {}",
                        rounds_processed
                    )));
                }
            }
            rounds_processed += 1;
        }
        if let Err(cleanup_error) = self.cleanup_all_resources().await {
            tracing::error!(target: "punch", %punch_pair, %cleanup_error, "Failed to cleanup resources after port prediction");
        }
        tracing::debug!(target: "punch", %punch_pair, rounds_processed, "Port prediction completed without success");
        last_error.map_or(Ok(None), Err)
    }

    async fn allocate_and_probe(
        &mut self,
        punch_pair: Link,
        packet_send_fn: &PacketSendFn,
        interfaces_count: usize,
    ) -> io::Result<Vec<QuicInterface>> {
        let interfaces_count = interfaces_count.min(self.max_total as usize - self.total_created);
        tracing::debug!(target: "punch", %punch_pair, interfaces_count, "Allocating interfaces");

        let mut interfaces = Vec::new();
        for _i in 0..interfaces_count {
            match self.create_single_interface().await {
                Ok((bind_uri, iface)) => {
                    if let Ok(qbase::net::addr::RealAddr::Internet(socket_addr)) = iface.real_addr()
                    {
                        let port = socket_addr.port();
                        self.ports.push_back((
                            port,
                            bind_uri,
                            iface.clone(),
                            tokio::time::Instant::now(),
                        ));
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

        match self
            .send_batch_packets(&interfaces, punch_pair, packet_send_fn)
            .await
        {
            Ok(()) => {
                tracing::debug!(target: "punch", %punch_pair, packets_sent = interfaces.len(), "Packets sent successfully");
            }
            Err(e) => {
                tracing::error!(target: "punch", %punch_pair, %e, "Failed to send packets");
                for _ in 0..interfaces.len() {
                    if let Some((port, bind_uri, _iface, _)) = self.ports.pop_back() {
                        self.ifaces.unbind(bind_uri).await;
                        if let Err(cleanup_err) = self.release_quota() {
                            tracing::warn!(target: "punch", %cleanup_err, port, "Failed to cleanup port after packet send failure");
                        }
                    }
                }
                return Err(e);
            }
        }
        Ok(interfaces)
    }

    async fn create_single_interface(&mut self) -> io::Result<(BindUri, QuicInterface)> {
        self.recycle_expired_interfaces().await?;
        self.recycle_if_full().await?;

        // Request quota just-in-time before creating interface
        self.request_quota().await?;

        loop {
            let port = rand::random::<u16>() % (u16::MAX - 1024) + 1024;
            if self.ports.iter().any(|(p, _, _, _)| *p == port) {
                continue;
            }
            let bind_addr = self.port_to_bind_uri(port);
            let iface = self
                .ifaces
                .bind(bind_addr.clone(), self.factory.clone())
                .await
                .borrow();

            match iface.real_addr() {
                Ok(real_addr) => {
                    tracing::debug!(target: "punch", %bind_addr, %real_addr, "Created new interface");
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

    async fn send_batch_packets(
        &self,
        interfaces: &[QuicInterface],
        punch_pair: Link,
        packet_send_fn: &PacketSendFn,
    ) -> io::Result<()> {
        tracing::debug!(target: "punch", %punch_pair, interface_count = interfaces.len(), "Sending packets");
        let mut successful_sends = 0;
        for iface in interfaces {
            if let Ok(qbase::net::addr::RealAddr::Internet(socket_addr)) = iface.real_addr() {
                let link = Link::new(socket_addr, punch_pair.dst());
                let frame = TraversalFrame::Konck(KonckFrame::new(punch_pair));
                if packet_send_fn(iface, link, 64, frame).await.is_ok() {
                    successful_sends += 1;
                }
            }
        }
        tracing::debug!(target: "punch", %punch_pair, successful_sends, 
                      failed_sends = interfaces.len() - successful_sends,
                      total_interfaces = interfaces.len(), "Packet sending completed");
        if successful_sends > 0 || interfaces.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "Failed to send packets to all {} interfaces",
                interfaces.len()
            )))
        }
    }

    async fn cleanup_all_resources(&mut self) -> io::Result<()> {
        tracing::debug!(target: "punch", active_ports = self.ports.len(), 
                      "Starting resource cleanup");
        while let Some((port, bind_uri, _iface, _)) = self.ports.pop_front() {
            self.ifaces.unbind(bind_uri).await;
            if let Err(e) = self.release_quota() {
                tracing::warn!(target: "punch", %e, port, "Failed to release quota for interface");
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
        tracing::debug!(target: "punch", "Released 1 quota unit to scheduler");
        Ok(())
    }

    async fn request_quota(&mut self) -> io::Result<()> {
        if self.total_created as u32 + 1 > self.max_total {
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
        tracing::debug!(target: "punch", "Requested and allocated 1 quota unit from scheduler");
        Ok(())
    }
}

impl Drop for PortPredictor {
    fn drop(&mut self) {
        let futures: Vec<_> = self
            .ports
            .iter()
            .map(|(_, bind_uri, _, _)| self.ifaces.unbind(bind_uri.clone()))
            .collect();
        if !futures.is_empty() {
            tokio::spawn(async move {
                futures::future::join_all(futures).await;
            });
        }
    }
}
