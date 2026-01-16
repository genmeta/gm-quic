use std::{
    future::poll_fn,
    io::{self},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, atomic::AtomicBool},
    task::{Context, Poll, ready},
    time::Duration,
};

use qbase::{net::route::SocketEndpointAddr, varint::VarInt};
use qinterface::{
    Interface, RefInterface,
    local::Locations,
    logical::{QuicInterface, RebindedError, WeakQuicInterface, component::Component},
};
use thiserror::Error;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use super::{router::StunRouter, tx::Transaction};
use crate::{
    future::Future,
    nat::{iface::StunIO, msg::Request, router::StunRouterComponent},
};

#[derive(Error, Debug, Clone)]
#[error(transparent)]
struct ArcIoError(Arc<io::Error>);

impl From<io::Error> for ArcIoError {
    fn from(source: io::Error) -> Self {
        Self(source.into())
    }
}

impl From<ArcIoError> for io::Error {
    fn from(source: ArcIoError) -> io::Error {
        io::Error::other(source)
    }
}

#[derive(Debug)]
struct RunningClient<IO: RefInterface + 'static> {
    #[allow(clippy::type_complexity)]
    keep_alive_task: Option<(AbortOnDropHandle<()>, SocketAddr)>,
    outer_addr: Arc<Future<Result<SocketAddr, ArcIoError>>>,
    nat_detect_task: Option<AbortOnDropHandle<()>>,
    nat_type: Arc<Future<Result<NatType, ArcIoError>>>,
    ref_iface: IO,
    // 可能被复制进keep_alive_task
    stun_router: StunRouter,
    stun_server: SocketAddr,
}

impl<IO: RefInterface + 'static> RunningClient<IO> {
    fn new(ref_iface: IO, stun_router: StunRouter, stun_server: SocketAddr) -> Self {
        Self {
            nat_type: Default::default(),
            outer_addr: Default::default(),
            stun_server,
            ref_iface,
            stun_router,
            keep_alive_task: Default::default(),
            nat_detect_task: Default::default(),
        }
    }

    fn keep_alive_task(
        &self,
    ) -> io::Result<(impl futures::Future<Output = ()> + use<IO>, SocketAddr)> {
        let outer_addr = self.outer_addr.clone();
        let stun_server = self.stun_server;
        let stun_router = self.stun_router.clone();

        let ref_iface = self.ref_iface.clone();
        let bind_uri = ref_iface.iface().bind_uri();
        let real_addr = ref_iface.iface().local_addr()?;

        let keep_alive_task = async move {
            let handle_detect_result = |detect_result: &io::Result<SocketAddr>| match &detect_result
            {
                Ok(new_outer_addr) => {
                    let ep = SocketEndpointAddr::Agent {
                        agent: stun_server,
                        outer: (*new_outer_addr),
                    };

                    match outer_addr.try_get().as_deref().cloned() {
                        Some(Ok(old_outer)) if old_outer == *new_outer_addr => {
                            tracing::debug!(target: "stun", %new_outer_addr,  "Keep alive, outer addr unchanged");
                        }
                        Some(old_state) => {
                            tracing::debug!(target: "stun", ?old_state, %new_outer_addr, "Keep alive, outer addr changed");
                            outer_addr.assign(Ok(*new_outer_addr));
                            if !bind_uri.is_temporary() {
                                // todo: get location from interface component
                                Locations::global().upsert(bind_uri.clone(), Arc::new(ep));
                            }
                        }
                        None => {
                            tracing::debug!(target: "stun", %new_outer_addr, "Detected outer addr");
                            outer_addr.assign(Ok(*new_outer_addr));
                            if !bind_uri.is_temporary() {
                                Locations::global().upsert(bind_uri.clone(), Arc::new(ep));
                            }
                        }
                    }
                }
                Err(error) => {
                    tracing::debug!(target: "stun", ?error, "Detect outer addr failed");
                    Locations::global().remove::<SocketEndpointAddr>(bind_uri.clone());
                }
            };
            tracing::debug!(target: "stun", "Starting keep alive task");
            loop {
                let detect_result = detect_outer_addr(
                    ref_iface.clone(),
                    stun_router.clone(),
                    stun_server,
                    3,
                    Duration::from_millis(300),
                )
                .await;

                handle_detect_result(&detect_result);

                let timeout = match detect_result {
                    Ok(_) => Duration::from_secs(30),
                    Err(_) => Duration::from_secs(1),
                };
                outer_addr.assign(detect_result.map_err(ArcIoError::from));
                tokio::time::sleep(timeout).await;
            }
        };
        let bind_uri = self.ref_iface.iface().bind_uri();
        let keep_alive_task = keep_alive_task.instrument(tracing::debug_span!(
            target: "stun",
            "keep_alive_task",
            %bind_uri,
            %stun_server,
        ));

        Ok((keep_alive_task, real_addr))
    }

    fn respawn_keep_alive_task(&mut self) -> io::Result<()> {
        let (task, real_addr) = self.keep_alive_task()?;
        self.keep_alive_task = Some((AbortOnDropHandle::new(tokio::spawn(task)), real_addr));
        Ok(())
    }

    fn poll_outer_addr(&mut self, cx: &mut Context) -> Poll<io::Result<SocketAddr>> {
        if self.keep_alive_task.is_none() {
            self.respawn_keep_alive_task()?;
        }
        self.outer_addr
            .poll_get(cx)
            .map(|result| result.clone().map_err(io::Error::from))
    }

    fn get_outer_addr(&mut self) -> Option<io::Result<SocketAddr>> {
        if self.keep_alive_task.is_none()
            && let Err(error) = self.respawn_keep_alive_task()
        {
            return Some(Err(error));
        }

        self.outer_addr
            .try_get()
            .map(|result| result.clone().map_err(io::Error::from))
    }

    fn nat_detect_task(&self) -> io::Result<impl futures::Future<Output = ()> + use<IO>> {
        let nat_type = self.nat_type.clone();
        let ref_iface = self.ref_iface.clone();
        let stun_router = self.stun_router.clone();
        let stun_server = self.stun_server;
        let bind_uri = ref_iface.iface().bind_uri();
        // Note: 原来的逻辑是 nat 探测会新建 iface，但是有的服务器只能开放指定端口，所以还是用监听的端口进行探测
        // 又因为Dynamic 总是会新建 iface 进行打洞，所以这里污染了影响不会很大
        let task = async move {
            tracing::debug!(target: "stun", "Starting NAT type detection");
            let timeout = Duration::from_millis(100);
            _ = nat_type.assign(
                detect_nat_type(ref_iface, stun_router, stun_server, 30, timeout)
                    .await
                    .map_err(ArcIoError::from),
            );
        };

        Ok(task.instrument(tracing::debug_span!(
            target: "stun",
            "nat_type_task",
            bind_uri=%bind_uri,
            %stun_server,
        )))
    }

    fn respawn_nat_detect_task(&mut self) -> io::Result<()> {
        let task = self.nat_detect_task()?;
        self.nat_detect_task = Some(AbortOnDropHandle::new(tokio::spawn(task)));
        Ok(())
    }

    fn poll_nat_type(&mut self, cx: &mut Context) -> Poll<io::Result<NatType>> {
        if self.nat_detect_task.is_none() {
            self.respawn_nat_detect_task()?;
        }
        self.nat_type
            .poll_get(cx)
            .map(|result| result.clone().map_err(io::Error::from))
    }

    pub fn get_nat_type(&mut self) -> Option<io::Result<NatType>> {
        if self.nat_detect_task.is_none()
            && let Err(error) = self.respawn_nat_detect_task()
        {
            return Some(Err(error));
        }
        self.nat_type
            .try_get()
            .map(|result| result.clone().map_err(io::Error::from))
    }

    fn restart(&mut self) -> io::Result<()> {
        self.stun_router.clear();
        *self = RunningClient::new(
            self.ref_iface.clone(),
            self.stun_router.clone(),
            self.stun_server,
        );
        self.respawn_nat_detect_task()?;
        self.respawn_keep_alive_task()?;
        Ok(())
    }

    fn close(&mut self) -> ClosingClient {
        let keep_alive_task = self.keep_alive_task.take().map(|(task, _)| task);
        let nat_detect_task = self.nat_detect_task.take();
        ClosingClient {
            keep_alive_task,
            nat_detect_task,
        }
    }
}

impl<IO: RefInterface + 'static> Drop for RunningClient<IO> {
    fn drop(&mut self) {
        tracing::debug!(target: "stun", bind_uri = %self.ref_iface.iface().bind_uri(), "Drop stun client");
        // Locations::global().remove::<SocketEndpointAddr>(&self.protocol.bind_uri());
        // all addresses removed by qinterface::Interface::drop
    }
}

#[derive(Debug)]
struct ClosingClient {
    keep_alive_task: Option<AbortOnDropHandle<()>>,
    nat_detect_task: Option<AbortOnDropHandle<()>>,
}

impl ClosingClient {
    pub fn poll_close(&mut self, cx: &mut Context) -> Poll<()> {
        if let Some(task) = self.keep_alive_task.as_mut() {
            task.abort();
            _ = ready!(Pin::new(task).poll(cx));
            // avoid poll after completion
            self.keep_alive_task = None;
        }
        if let Some(task) = self.nat_detect_task.as_mut() {
            task.abort();
            _ = ready!(Pin::new(task).poll(cx));
            // avoid poll after completion
            self.nat_detect_task = None;
        }
        Poll::Ready(())
    }
}

#[derive(Debug)]
enum State<IO: RefInterface + 'static> {
    Running(RunningClient<IO>),
    Closing(ClosingClient),
}

impl<IO: RefInterface + 'static> Default for State<IO> {
    fn default() -> Self {
        Self::Closing(ClosingClient {
            keep_alive_task: None,
            nat_detect_task: None,
        })
    }
}

impl<IO: RefInterface + 'static> State<IO> {
    pub fn poll_close(&mut self, cx: &mut Context) -> Poll<()> {
        loop {
            match self {
                State::Running(client) => *self = Self::Closing(client.close()),
                State::Closing(client) => return client.poll_close(cx),
            }
        }
    }

    fn map<T>(&mut self, f: impl FnOnce(&mut RunningClient<IO>) -> T) -> io::Result<T> {
        match self {
            State::Running(client) => Ok(f(client)),
            State::Closing(..) => Err(RebindedError.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StunClient<IO: RefInterface + 'static> {
    state: Arc<Mutex<State<IO>>>,
}

impl<IO: RefInterface + 'static> Default for StunClient<IO> {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(Default::default())),
        }
    }
}

impl<IO: RefInterface + 'static> StunClient<IO> {
    pub fn new(ref_iface: IO, stun_router: StunRouter, stun_server: SocketAddr) -> Self {
        let state = State::Running(RunningClient::new(ref_iface, stun_router, stun_server));
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, State<IO>> {
        self.state.lock().unwrap()
    }

    pub fn poll_outer_addr(&self, cx: &mut Context) -> Poll<io::Result<SocketAddr>> {
        self.lock_state().map(|client| client.poll_outer_addr(cx))?
    }

    pub fn get_outer_addr(&self) -> Option<io::Result<SocketAddr>> {
        match self.lock_state().map(|client| client.get_outer_addr()) {
            Ok(option) => option,
            Err(error) => Some(Err(error)),
        }
    }

    pub async fn outer_addr(&self) -> io::Result<SocketAddr> {
        poll_fn(|cx| self.poll_outer_addr(cx)).await
    }

    pub fn get_nat_type(&self) -> Option<io::Result<NatType>> {
        match self.lock_state().map(|client| client.get_nat_type()) {
            Ok(option) => option,
            Err(error) => Some(Err(error)),
        }
    }

    pub fn poll_nat_type(&self, cx: &mut Context) -> Poll<io::Result<NatType>> {
        self.lock_state().map(|client| client.poll_nat_type(cx))?
    }

    pub async fn nat_type(&self) -> io::Result<NatType> {
        poll_fn(|cx| self.poll_nat_type(cx)).await
    }

    pub fn agent(&self) -> io::Result<SocketAddr> {
        self.lock_state().map(|client| client.stun_server)
    }

    pub fn restart(&self) -> io::Result<()> {
        self.lock_state().map(|client| client.restart())?
    }

    pub fn poll_close(&self, cx: &mut Context) -> Poll<()> {
        self.lock_state().poll_close(cx)
    }

    pub fn io(&self) -> io::Result<IO> {
        self.lock_state().map(|client| client.ref_iface.clone())
    }
}

// impl Component for StunClient {
//     fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
//         self.lock_state().poll_close(cx)
//     }

//     fn reinit(&self, quic_iface: &QuicInterface) {
//         match StunProtocol::try_from(quic_iface) {
//             Ok(protocol) => {
//                 *self.lock_state() = State::Running(RunningClient::new(protocol, self.stun_server))
//             }
//             Err(error) => {
//                 tracing::warn!(target: "stun", %error, "StunClient reinit skipped")
//             }
//         }
//     }
// }

#[derive(Debug)]
pub struct StunClientComponent {
    stun_server: SocketAddr,
    client: Mutex<StunClient<WeakQuicInterface>>,
}

impl StunClientComponent {
    pub fn new(
        weak_iface: WeakQuicInterface,
        stun_router: StunRouter,
        stun_server: SocketAddr,
    ) -> Self {
        let client = StunClient::new(weak_iface, stun_router, stun_server);
        Self {
            stun_server,
            client: Mutex::new(client),
        }
    }

    fn lock(&self) -> MutexGuard<'_, StunClient<WeakQuicInterface>> {
        self.client
            .lock()
            .expect("StunClientComponent mutex poisoned")
    }

    pub fn client(&self) -> StunClient<WeakQuicInterface> {
        self.lock().clone()
    }
}

impl Component for StunClientComponent {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.lock().poll_close(cx)
    }

    fn reinit(&self, quic_iface: &QuicInterface) {
        let mut client = self.lock();
        match quic_iface.with_component(|spc: &StunRouterComponent| {
            spc.reinit(quic_iface);
            (spc.router(), spc.iface())
        }) {
            Ok(Some((.., iface))) if client.io().is_ok_and(|exist| exist.same_io(&iface)) => {}
            Ok(Some((router, iface))) => *client = StunClient::new(iface, router, self.stun_server),
            Ok(None) | Err(..) => *client = StunClient::default(),
        }
    }
}

fn no_response_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "No response from STUN server")
}

async fn detect_outer_addr<IO: RefInterface>(
    ref_iface: IO,
    stun_router: StunRouter,
    stun_server: SocketAddr,
    retry_times: u8,
    timeout: Duration,
) -> io::Result<SocketAddr> {
    let request = Request::default();
    let response = Transaction::begin(ref_iface, stun_router, retry_times, timeout)
        .send_request(request, stun_server)
        .await?
        .ok_or_else(no_response_error)?;
    response.map_addr()
}

pub static VISUALIZE_NAT_DETECTION: AtomicBool = AtomicBool::new(false);

macro_rules! visualize_nat_detection {
    ($($tt:tt)*) => {{
        if VISUALIZE_NAT_DETECTION.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::info!($($tt)*);
        } else {
            tracing::debug!(target: "stun", $($tt)*);
        }
    }};
}

pub const RESTRICTED_RETRY_TIMES: u8 = 3;

async fn detect_nat_type<IO: RefInterface>(
    ref_iface: IO,
    stun_router: StunRouter,
    stun_server: SocketAddr,
    retry_times: u8,
    timeout: Duration,
) -> io::Result<NatType> {
    let local_addr = ref_iface.iface().local_addr()?;
    visualize_nat_detection!("Starting NAT detection with local address: {local_addr}");
    let stun_server1 = stun_server;

    visualize_nat_detection!("Access Test: probing server {stun_server1}");
    let request = Request::default();
    let response = Transaction::begin(ref_iface.clone(), stun_router.clone(), retry_times, timeout)
        .send_request(request, stun_server1)
        .await?;

    let Some(response) = response else {
        visualize_nat_detection!("Result: No response after {retry_times} attempts");
        visualize_nat_detection!(
            "Conclusion: The network feature is {:?}, NAT Type is {:?}\n",
            NetFeature::Blocked,
            NatType::Blocked
        );
        return Ok(NatType::Blocked);
    };

    let mut net_features = NetFeature::empty();

    let mapped_addr1 = response.map_addr()?;
    let stun_server2 = response.changed_addr()?;
    visualize_nat_detection!("Result: Received from {stun_server1}, external addr: {mapped_addr1}");
    if mapped_addr1 == local_addr {
        // Public IP
        visualize_nat_detection!(
            "Conclusion: Address {local_addr} has public IP, Proceeding to filtering behavior test.\n"
        );
        visualize_nat_detection!(
            "Filtering Test: probing server {stun_server2}. Request server to respond from a changed IP:port",
        );
        net_features |= NetFeature::Public;
        let request = Request::change_ip_and_port();
        let response =
            Transaction::begin(ref_iface.clone(), stun_router.clone(), retry_times, timeout)
                .send_request(request, stun_server2)
                .await?;
        if let Some(response) = response {
            let mapped_addr2 = response.map_addr()?;
            visualize_nat_detection!(
                "Result: received from {}, external addr: {mapped_addr2}",
                response.source_addr()?
            );
            visualize_nat_detection!("Conclusion: Destination IP independent filtering\n");
        } else {
            net_features |= NetFeature::Restricted;
            visualize_nat_detection!("Result: No response after {retry_times} attempts");
            visualize_nat_detection!("Conclusion: Filters packets based on destination IP\n");
        }
        visualize_nat_detection!(
            "Filtering Test: probing server {stun_server2}. Request server to respond from a changed port",
        );
        let request = Request::change_port();
        let response =
            Transaction::begin(ref_iface.clone(), stun_router.clone(), retry_times, timeout)
                .send_request(request, stun_server2)
                .await?;
        if let Some(response) = response {
            let mapped_addr2 = response.map_addr()?;
            visualize_nat_detection!(
                "Result: received from {}, external addr: {mapped_addr2}",
                response.source_addr()?
            );
            visualize_nat_detection!("Conclusion: Destination port independent filtering\n");
        } else {
            net_features |= NetFeature::PortRestricted;
            visualize_nat_detection!("Result: No response after {retry_times} attempts");
            visualize_nat_detection!("Conclusion: Filters packets based on destination port\n");
        }
        tracing::info!(
            target: "stun",
            "NAT detection completed. Network features: {:?}, NAT Type: {:?}",
            net_features,
            NatType::from(net_features)
        );
        Ok(net_features.into())
    } else {
        // Private IP
        visualize_nat_detection!("Conclusion: Address {local_addr} has private IP.\n");
        visualize_nat_detection!("Mapping Test1: probing server {stun_server2}");
        let request = Request::default();
        let response =
            Transaction::begin(ref_iface.clone(), stun_router.clone(), retry_times, timeout)
                .send_request(request, stun_server2)
                .await?
                .ok_or_else(no_response_error)?;

        let stun_server3 = response.changed_addr()?;
        let mapped_addr2 = response.map_addr()?;
        if mapped_addr1 != mapped_addr2 {
            net_features |= NetFeature::Symmetric;
            visualize_nat_detection!(
                "Result: Received from {stun_server2}, external addr: {mapped_addr2}"
            );
            visualize_nat_detection!(
                "Conclusion: The mapped address is different and destination-dependent.\n"
            );

            // 判断规律
            visualize_nat_detection!("Mapping Test2: probing server {stun_server3}");
            let request = Request::default();
            let response =
                Transaction::begin(ref_iface.clone(), stun_router.clone(), retry_times, timeout)
                    .send_request(request, stun_server3)
                    .await?;

            let Some(response) = response else {
                visualize_nat_detection!("Result: No response after {retry_times} attempts");
                visualize_nat_detection!(
                    "Conclusion: Unable to determine port mapping behavior due to lack of response from third server.\n"
                );
                return Ok(net_features.into());
            };

            let mapped_addr3 = response.map_addr()?;
            let step1 = mapped_addr2.port() as i32 - mapped_addr1.port() as i32;
            let step2 = mapped_addr3.port() as i32 - mapped_addr2.port() as i32;
            visualize_nat_detection!(
                "Result: Received from {stun_server3}, external addr: {mapped_addr3}"
            );
            if step1 == step2 {
                visualize_nat_detection!(
                    "Conclusion: The port changes regularly with step {step1}\n"
                );
            } else {
                visualize_nat_detection!("Conclusion: The Ports change randomly.\n");
            }
            Ok(net_features.into())
        } else {
            // 不是对称型
            // Open test
            // 发给 server2 换 ip and port 即 server3 回, server3 可能不响应
            // server1: ip1:port1
            // server2: ip2:port2
            // server3: ip3:port1
            // server4: ip1:port2
            // server5: ip2:port1
            // server6: ip3:port2
            visualize_nat_detection!(
                "Filtering Test: probing server {stun_server2}. Request server to respond from a changed IP and port",
            );
            let request = Request::change_ip_and_port();
            // 可能会不响应，超时太久会导致探测很久
            let response = Transaction::begin(
                ref_iface.clone(),
                stun_router.clone(),
                RESTRICTED_RETRY_TIMES,
                timeout,
            )
            .send_request(request, stun_server2)
            .await?;
            if let Some(response) = response {
                let mapped_addr2 = response.map_addr()?;
                visualize_nat_detection!(
                    "Result: received from {}, external addr: {mapped_addr2}",
                    response.source_addr()?
                );
                visualize_nat_detection!("Conclusion: Destination IP independent filtering\n");
            } else {
                net_features |= NetFeature::Restricted;
                visualize_nat_detection!(
                    "Result: No response after {RESTRICTED_RETRY_TIMES} attempts"
                );
                visualize_nat_detection!("Conclusion: Filters packets based on destination IP\n");
            }
            visualize_nat_detection!(
                "Filtering Test: probing server {stun_server2}. Request server to respond from a changed port",
            );
            // Restricted test
            // server2 换 port 即 server5 回，可能不响应
            // 可能会不响应，超时太久会导致探测很久
            let request = Request::change_port();
            let response = Transaction::begin(
                ref_iface.clone(),
                stun_router.clone(),
                RESTRICTED_RETRY_TIMES,
                timeout,
            )
            .send_request(request, stun_server2)
            .await?;
            if let Some(response) = response {
                let mapped_addr2 = response.map_addr()?;
                visualize_nat_detection!(
                    "Result: received from {}, external addr: {mapped_addr2}",
                    response.source_addr()?
                );
                visualize_nat_detection!("Conclusion: Destination port independent filtering\n");
            } else {
                net_features |= NetFeature::PortRestricted;
                visualize_nat_detection!(
                    "Result: No response after {RESTRICTED_RETRY_TIMES} attempts"
                );
                visualize_nat_detection!("Conclusion: Filters packets based on destination port\n");
            }
            // dynamic test， 请求 server3
            visualize_nat_detection!("Dynamic Test: probing server {stun_server3}",);
            let request = Request::default();
            let response =
                Transaction::begin(ref_iface.clone(), stun_router.clone(), retry_times, timeout)
                    .send_request(request, stun_server3)
                    .await?;

            if let Some(response) = response {
                // 回包，但是映射地址不一致，为动态型
                let mapped_addr3 = response.map_addr()?;
                visualize_nat_detection!(
                    "Result: received from {}, external addr: {mapped_addr3}",
                    response.source_addr()?
                );
                if mapped_addr1 != mapped_addr3 {
                    net_features |= NetFeature::Dynamic;
                    visualize_nat_detection!(
                        "Conclusion: Mapping inconsistency indicates Address-Dependent Mapping, a Dynamic NAT type\n"
                    );
                } else {
                    visualize_nat_detection!(
                        "Conclusion: The mapping address is consistent, not Dynamic\n"
                    );
                }
            } else {
                // 不回包也视为动态型
                net_features |= NetFeature::Dynamic;
                visualize_nat_detection!("Result: No response after 3 attempts");
                visualize_nat_detection!(
                    "Conclusion: Absence of server response may indicates Dynamic NAT behavior\n"
                );
            }
            tracing::info!(
                target: "stun",
                "NAT detection completed. Network features: {:?}, NAT Type: {:?}",
                net_features,
                NatType::from(net_features)
            );
            Ok(net_features.into())
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NatType {
    Blocked = 0x00,
    FullCone = 0x01,
    RestrictedCone = 0x02,
    RestrictedPort = 0x03,
    Symmetric = 0x04,
    Dynamic = 0x05,
}

impl From<NatType> for VarInt {
    fn from(nat_type: NatType) -> Self {
        VarInt::from(nat_type as u8)
    }
}

impl TryFrom<u8> for NatType {
    type Error = io::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(NatType::Blocked),
            0x01 => Ok(NatType::FullCone),
            0x02 => Ok(NatType::RestrictedCone),
            0x03 => Ok(NatType::RestrictedPort),
            0x04 => Ok(NatType::Symmetric),
            0x05 => Ok(NatType::Dynamic),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid value for NatType",
            )),
        }
    }
}

impl TryFrom<VarInt> for NatType {
    type Error = io::Error;

    fn try_from(value: VarInt) -> Result<Self, Self::Error> {
        Self::try_from(value.into_inner() as u8)
    }
}

impl From<NetFeature> for NatType {
    fn from(value: NetFeature) -> Self {
        if value.contains(NetFeature::Blocked) {
            NatType::Blocked
        } else if value.contains(NetFeature::Symmetric) {
            NatType::Symmetric
        } else if value.contains(NetFeature::Dynamic) {
            NatType::Dynamic
        } else if value.contains(NetFeature::PortRestricted) {
            NatType::RestrictedPort
        } else if value.contains(NetFeature::Restricted) {
            NatType::RestrictedCone
        } else {
            NatType::FullCone
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug,Clone, Copy, PartialEq, Eq)]
    struct NetFeature: u8 {
        const Blocked = 0x01;
        const Public = 0x02;
        const Restricted = 0x04;
        const PortRestricted = 0x08;
        const Symmetric =0x10;
        const Dynamic = 0x20;
    }
}
