#![allow(unused)]

use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use qbase::net::{
    addr::RealAddr,
    route::{Link, PacketHeader, Pathway},
};
use qinterface::{Interface, bind_uri::BindUri, component::Component, device::Devices, io::IO};
use tokio::{runtime::Runtime, sync::Notify, time};

pub fn run<F: Future>(future: F) -> F::Output {
    static RT: std::sync::LazyLock<Runtime> = std::sync::LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    });

    RT.block_on(async move {
        match time::timeout(Duration::from_secs(30), future).await {
            Ok(output) => output,
            Err(_timedout) => panic!("test timed out"),
        }
    })
}

pub fn test_bind_uri() -> BindUri {
    // inet scheme is easiest & does not require real interfaces
    let base: BindUri = "inet://127.0.0.1:0".into();
    base.alloc_port()
}

pub fn any_iface_bind_uri() -> Option<BindUri> {
    let devices = Devices::global();
    let interfaces = devices.interfaces();

    // prefer v4 for simplicity
    for (name, iface) in &interfaces {
        if !iface.ipv4.is_empty() {
            return Some(format!("iface://v4.{name}:0").as_str().into());
        }
    }

    // fallback v6 (non-link-local selection happens in resolve())
    for (name, iface) in &interfaces {
        if !iface.ipv6.is_empty() {
            return Some(format!("iface://v6.{name}:0").as_str().into());
        }
    }

    None
}

#[derive(Debug, Default)]
pub struct FakeIoState {
    pub generation: AtomicUsize,
    pub close_calls: AtomicUsize,
}

#[derive(Debug)]
pub struct FakeIo {
    bind_uri: BindUri,
    real_addr: RealAddr,
    state: Arc<FakeIoState>,
    closed: AtomicBool,
    close_notify: Arc<Notify>,
}

impl FakeIo {
    pub fn new(bind_uri: BindUri, real_addr: RealAddr, state: Arc<FakeIoState>) -> Self {
        Self {
            bind_uri,
            real_addr,
            state,
            closed: AtomicBool::new(false),
            close_notify: Arc::new(Notify::new()),
        }
    }

    pub fn close_notify(&self) -> Arc<Notify> {
        self.close_notify.clone()
    }
}

impl IO for FakeIo {
    fn bind_uri(&self) -> BindUri {
        self.bind_uri.clone()
    }

    fn real_addr(&self) -> io::Result<RealAddr> {
        Ok(self.real_addr)
    }

    fn max_segment_size(&self) -> io::Result<usize> {
        Ok(1500)
    }

    fn max_segments(&self) -> io::Result<usize> {
        Ok(1)
    }

    fn poll_send(
        &self,
        _cx: &mut Context,
        pkts: &[io::IoSlice],
        _hdr: PacketHeader,
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(pkts.len()))
    }

    fn poll_recv(
        &self,
        _cx: &mut Context,
        _pkts: &mut [BytesMut],
        _hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_close(&mut self, _cx: &mut Context) -> Poll<io::Result<()>> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.state.close_calls.fetch_add(1, Ordering::SeqCst);
            self.close_notify.notify_waiters();
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Clone)]
pub struct FakeFactory {
    pub state: Arc<FakeIoState>,
    pub base_port: u16,
}

impl FakeFactory {
    pub fn new() -> Self {
        Self {
            state: Arc::new(FakeIoState::default()),
            base_port: 50000,
        }
    }
}

impl qinterface::io::ProductIO for FakeFactory {
    fn bind(&self, bind_uri: BindUri) -> Box<dyn IO> {
        let generation = self.state.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let real_addr = RealAddr::Internet(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            self.base_port.saturating_add(generation as u16),
        ));
        Box::new(FakeIo::new(bind_uri, real_addr, self.state.clone()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeEventKind {
    Reinit,
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct ProbeEvent {
    pub kind: ProbeEventKind,
    pub bind_uri: BindUri,
}

#[derive(Debug, Default)]
pub struct Probe {
    pub shutdown_calls: AtomicUsize,
    pub reinit_calls: AtomicUsize,
    pub events: Mutex<Vec<ProbeEvent>>,
    pub last_bind_uri: Mutex<Option<BindUri>>,
}

#[derive(Debug, Clone)]
pub struct ProbeComponent {
    pub probe: Arc<Probe>,
}

impl ProbeComponent {
    pub fn new(probe: Arc<Probe>) -> Self {
        Self { probe }
    }
}

impl Component for ProbeComponent {
    fn poll_shutdown(&self, _cx: &mut Context<'_>) -> Poll<()> {
        self.probe.shutdown_calls.fetch_add(1, Ordering::SeqCst);
        let bind_uri = self
            .probe
            .last_bind_uri
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(test_bind_uri);
        self.probe.events.lock().unwrap().push(ProbeEvent {
            kind: ProbeEventKind::Shutdown,
            bind_uri,
        });
        Poll::Ready(())
    }

    fn reinit(&self, iface: &Interface) {
        self.probe.reinit_calls.fetch_add(1, Ordering::SeqCst);
        *self.probe.last_bind_uri.lock().unwrap() = Some(iface.bind_uri());
        self.probe.events.lock().unwrap().push(ProbeEvent {
            kind: ProbeEventKind::Reinit,
            bind_uri: iface.bind_uri(),
        });
    }
}

pub fn dummy_packet_header() -> PacketHeader {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    let way = Pathway::new(addr.into(), addr.into());
    let link = Link::new(addr.into(), addr.into());
    PacketHeader::new(way, link, 64, None, 0)
}
