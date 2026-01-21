// use std::{
//     future::Future,
//     io,
//     net::SocketAddr,
//     path::PathBuf,
//     sync::{Arc, Mutex, OnceLock},
//     time::Duration,
// };

// use gm_quic::{
//     prelude::{
//         Connection, EndpointAddr, ParameterId, Pathway, QuicClient, QuicListeners,
//         SocketEndpointAddr,
//         handy::{LegacySeqLogger, ToCertificate},
//     },
//     qbase::param::{ClientParameters, ServerParameters},
//     qinterface::logical::QuicInterfaces,
//     qtraversal::{
//         iface::{StunInterface, TraversalFactory},
//         nat::{
//             StunIO,
//             client::{NatType, StunClient},
//         },
//     },
// };
// use rustls::RootCertStore;
// use tokio::{
//     io::{AsyncReadExt, AsyncWriteExt},
//     task::JoinError,
//     time,
// };
// use tracing::{info, warn};
// use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// #[derive(Debug, Clone, Copy)]
// pub struct TestCase {
//     pub bind_addr: &'static str,
//     pub outer_addr: &'static str,
//     pub nat_type: NatType,
// }

// pub const STUN_SERVERS: &str = "10.10.0.64:20002";

// pub const CASES: [TestCase; 10] = [
//     TestCase {
//         bind_addr: "192.168.0.98:6001",
//         outer_addr: "10.10.0.98:6001",
//         nat_type: NatType::FullCone,
//     },
//     TestCase {
//         bind_addr: "192.168.0.96:6002",
//         outer_addr: "10.10.0.96:6002",
//         nat_type: NatType::RestrictedCone,
//     },
//     TestCase {
//         bind_addr: "192.168.0.88:6003",
//         outer_addr: "10.10.0.88:6003",
//         nat_type: NatType::RestrictedPort,
//     },
//     TestCase {
//         bind_addr: "192.168.0.86:6004",
//         outer_addr: "10.10.0.86:6004",
//         nat_type: NatType::Dynamic,
//     },
//     TestCase {
//         bind_addr: "192.168.0.84:6005",
//         outer_addr: "10.10.0.84:6005",
//         nat_type: NatType::Symmetric,
//     },
//     TestCase {
//         bind_addr: "172.16.0.48:6006",
//         outer_addr: "10.10.0.48:6006",
//         nat_type: NatType::FullCone,
//     },
//     TestCase {
//         bind_addr: "172.16.0.46:6007",
//         outer_addr: "10.10.0.46:6007",
//         nat_type: NatType::RestrictedCone,
//     },
//     TestCase {
//         bind_addr: "172.16.0.38:6008",
//         outer_addr: "10.10.0.38:6008",
//         nat_type: NatType::RestrictedPort,
//     },
//     TestCase {
//         bind_addr: "172.16.0.36:6009",
//         outer_addr: "10.10.0.36:6009",
//         nat_type: NatType::Dynamic,
//     },
//     TestCase {
//         bind_addr: "172.16.0.34:6010",
//         outer_addr: "10.10.0.34:6010",
//         nat_type: NatType::Symmetric,
//     },
// ];

// pub fn init_logger() -> std::io::Result<()> {
//     let file = std::fs::OpenOptions::new()
//         .create(true)
//         .write(true)
//         .truncate(true)
//         .open("test.log")?;

//     let filter = tracing_subscriber::filter::filter_fn(|metadata| {
//         !metadata.target().contains("netlink_packet_route")
//     });

//     let _ = tracing_subscriber::registry()
//         .with(tracing_subscriber::Layer::with_filter(
//             tracing_subscriber::fmt::layer()
//                 .with_target(true)
//                 .with_ansi(false)
//                 .with_file(true)
//                 .with_line_number(true),
//             filter.clone(),
//         ))
//         .with(tracing_subscriber::Layer::with_filter(
//             tracing_subscriber::fmt::layer().with_writer(file),
//             filter,
//         ))
//         .try_init();
//     Ok(())
// }

// fn run<T: Send + 'static>(
//     future: impl Future<Output = T> + Send + 'static,
// ) -> Result<T, JoinError> {
//     static RT: OnceLock<Mutex<tokio::runtime::Runtime>> = OnceLock::new();
//     let rt = RT.get_or_init(|| {
//         Mutex::new(
//             tokio::runtime::Builder::new_multi_thread()
//                 .enable_all()
//                 .build()
//                 .unwrap(),
//         )
//     });
//     rt.lock()
//         .unwrap()
//         .block_on(async move { tokio::spawn(future).await })
// }

// async fn test_detect_case(case: usize) {
//     init_logger().unwrap();
//     let stun = STUN_SERVERS.parse().unwrap();
//     let case = CASES[case];
//     let socket_addr: SocketAddr = case.bind_addr.parse::<SocketAddr>().unwrap();
//     let bind_uri = format!("inet://{}", case.bind_addr);
//     let iface = Arc::new(StunInterface::new(socket_addr, bind_uri.into()).unwrap());
//     let client = StunClient::new(iface.stun_protocol().unwrap(), stun);
//     let outer_addr = client.outer_addr().await.expect("failed to get outer addr");
//     info!("Outer addr: {} Agent addr {}", outer_addr, stun);
//     let nat_type = client.nat_type().await.expect("failed to get nat type");
//     info!(
//         "bind addr: {} outer addr: {} NAT type: {:?} expected: {:?}",
//         case.bind_addr, case.outer_addr, nat_type, case.nat_type
//     );
//     assert!(nat_type == case.nat_type);
// }

// macro_rules! test_detect {
//     (async fn $test_name:ident = test_detect_case($case:expr) $($tt:tt)*) => {

//         #[test]
//         #[ignore]
//         fn $test_name() -> Result<(), JoinError> {
//             run(async move {
//                 test_detect_case($case).await
//             })
//         }

//         test_detect!($($tt)*);
//     };
//     () => {}
// }

// // ip netns exec nsa cargo test --package gm-quic test_detect -- --nocapture
// test_detect! {
//     async fn test_detect_full_cone_client = test_detect_case(0)
//     async fn test_detect_restricted_cone_client = test_detect_case(1)
//     async fn test_detect_port_restricted_client = test_detect_case(2)
//     async fn test_detect_dynamic_client = test_detect_case(3)
//     async fn test_detect_symmetric_client = test_detect_case(4)
//     async fn test_detect_full_cone_server = test_detect_case(5)
//     async fn test_detect_restricted_cone_server = test_detect_case(6)
//     async fn test_detect_port_restricted_server = test_detect_case(7)
//     async fn test_detect_dynamic_server = test_detect_case(8)
//     async fn test_detect_symmetric_server = test_detect_case(9)
// }

// const CLIENT_ADDR: [TestCase; 5] = [
//     CASES[0], // Full cone
//     CASES[1], // Restricted cone
//     CASES[2], // Port restricted
//     CASES[3], // Dynamic
//     CASES[4], // Symmetric
// ];

// const SERVER_ADDR: [TestCase; 5] = [
//     CASES[5], // Full cone
//     CASES[6], // Restricted cone
//     CASES[7], // Port restricted
//     CASES[8], // Dynamic
//     CASES[9], // Symmetric
// ];

// macro_rules! test_punch_pair {
//     (async fn $test_name:ident = test_punch_case($client:expr, $server:expr) $($tt:tt)*) => {

//         #[test]
//         #[ignore]
//         fn $test_name() -> Result<Result<(), TestError>, JoinError> {
//             run(async move {
//                 test_punch_case($client, $server).await
//             })
//         }

//         test_punch_pair!($($tt)*);
//     };
//     () => {}
// }

// // ip netns exec nsa cargo test --package gm-quic test_punch -- --nocapture
// test_punch_pair! {
//     async fn test_punch_full_cone_to_full_cone = test_punch_case(0, 0)
//     async fn test_punch_full_cone_to_restricted_cone = test_punch_case(0, 1)
//     async fn test_punch_full_cone_to_port_restricted = test_punch_case(0, 2)
//     async fn test_punch_full_cone_to_dynamic = test_punch_case(0, 3)
//     async fn test_punch_full_cone_to_symmetric = test_punch_case(0, 4)
//     async fn test_punch_restricted_cone_to_full_cone = test_punch_case(1, 0)
//     async fn test_punch_restricted_cone_to_restricted_cone = test_punch_case(1, 1)
//     async fn test_punch_restricted_cone_to_port_restricted = test_punch_case(1, 2)
//     async fn test_punch_restricted_cone_to_dynamic = test_punch_case(1, 3)
//     async fn test_punch_restricted_cone_to_symmetric = test_punch_case(1, 4)
//     async fn test_punch_port_restricted_to_full_cone = test_punch_case(2, 0)
//     async fn test_punch_port_restricted_to_restricted_cone = test_punch_case(2, 1)
//     async fn test_punch_port_restricted_to_port_restricted = test_punch_case(2, 2)
//     async fn test_punch_port_restricted_to_dynamic = test_punch_case(2, 3)
//      async fn test_punch_port_restricted_to_symmetric = test_punch_case(2, 4)
//     async fn test_punch_dynamic_to_full_cone = test_punch_case(3, 0)
//     async fn test_punch_dynamic_to_restricted_cone = test_punch_case(3, 1)
//     async fn test_punch_dynamic_to_port_restricted = test_punch_case(3, 2)
//     async fn test_punch_dynamic_to_dynamic = test_punch_case(3, 3)
//     async fn test_punch_dynamic_to_symmetric = test_punch_case(3, 4)
//     async fn test_punch_symmetric_to_full_cone = test_punch_case(4, 0)
//     async fn test_punch_symmetric_to_restricted_cone = test_punch_case(4, 1)
//     async fn test_punch_symmetric_to_port_restricted = test_punch_case(4, 2)
//     async fn test_punch_symmetric_to_dynamic = test_punch_case(4, 3)
//     async fn test_punch_symmetric_to_symmetric = test_punch_case(4, 4)
// }

// // #[tokio::test]
// // async fn test_punch() -> io::Result<()> {
// //     init_logger().unwrap();
// //     for (client, server) in (0..CLIENT_ADDR.len())
// //         .flat_map(|client| (0..SERVER_ADDR.len()).map(move |server| (client, server)))
// //     {
// //         info!(
// //             "Testing punch case: client {} ({:?}) <-> server {} ({:?})",
// //             client, CLIENT_ADDR[client].nat_type, server, SERVER_ADDR[server].nat_type
// //         );
// //         test_punch_case(client, server).await.unwrap();
// //     }
// //     Ok(())
// // }

// pub const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
// pub const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
// pub const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

// #[derive(thiserror::Error, Debug)]
// enum TestError {
//     #[error("operation timed out after {duration:?}")]
//     Timeout { duration: Duration },
//     #[error("Echo failed")]
//     Echo {
//         #[from]
//         source: EchoError,
//     },
//     #[error("Quic connection failed")]
//     Connection {
//         #[from]
//         source: gm_quic::prelude::Error,
//     },
//     #[error("No direct path established, paths: {paths:?}")]
//     NoDirectPath { paths: Vec<Pathway> },

//     #[error("Failed to get endpoint address")]
//     GetEndpointAddr {
//         #[from]
//         source: io::Error,
//     },
// }

// async fn test_punch_case(client: usize, server: usize) -> Result<(), TestError> {
//     init_logger().unwrap();

//     info!(
//         "Testing punch case: client {} ({:?}) <-> server {} ({:?})",
//         client, CLIENT_ADDR[client].nat_type, server, SERVER_ADDR[server].nat_type
//     );

//     if client == 3 || server == 3 {
//         warn!("Skipping Dynamic NAT test case");
//         // Dynamic NAT 模拟有问题
//         return Ok(());
//     }
//     if client == 4 && server == 4 {
//         warn!("Skipping Symmetric NAT to Symmetric NAT test case");
//         // Symmetric NAT 互穿不通
//         return Ok(());
//     }

//     let stun = STUN_SERVERS.parse().unwrap();
//     let client_addr: SocketAddr = CLIENT_ADDR[client].bind_addr.parse().unwrap();
//     let server_addr: SocketAddr = SERVER_ADDR[server].bind_addr.parse().unwrap();

//     let factory = TraversalFactory::initialize_global([stun].to_vec()).unwrap();
//     let server = QuicListeners::builder()
//         .with_qlog(Arc::new(LegacySeqLogger::new(PathBuf::from("./"))))
//         .with_iface_factory(factory.as_ref().clone())
//         .with_parameters(server_stream_unlimited_parameters())
//         .without_client_cert_verifier()
//         .listen(1000)
//         .unwrap();

//     server
//         .add_server("localhost", SERVER_CERT, SERVER_KEY, [server_addr], None)
//         .await
//         .unwrap();

//     tokio::spawn(serve_echo(server.clone()));
//     let server_iface = QuicInterfaces::global()
//         .borrow(&(server_addr.into()))
//         .unwrap();
//     info!("Server listening on {server_addr}");

//     let server_ep = std::future::poll_fn(|cx| server_iface.poll_endpoint_addr(cx)).await?;
//     let launch_client = launch_client(client_addr, EndpointAddr::Socket(server_ep));
//     let duration = Duration::from_secs(10);
//     let result = time::timeout(duration, launch_client)
//         .await
//         .map_err(|_| TestError::Timeout { duration });

//     server.shutdown();

//     result?
// }

// async fn launch_client(client_addr: SocketAddr, server_ep: EndpointAddr) -> Result<(), TestError> {
//     let stun = STUN_SERVERS.parse().unwrap();
//     let mut roots = RootCertStore::empty();
//     roots.add_parsable_certificates(CA_CERT.to_certificate());

//     let factory = TraversalFactory::initialize_global([stun].to_vec()).unwrap();
//     let client = QuicClient::builder()
//         .with_root_certificates(roots)
//         .without_cert()
//         .enable_sslkeylog()
//         .with_qlog(Arc::new(LegacySeqLogger::new(PathBuf::from("./"))))
//         .with_iface_factory(factory.as_ref().clone())
//         .with_parameters(client_stream_unlimited_parameters())
//         .bind([client_addr])
//         .await
//         .build();

//     // 不会进行绑定，不会出错
//     let connection = client.connected_to("localhost", [server_ep]).await.unwrap();
//     const DATA: &[u8] = include_bytes!("./lib.rs");
//     let test_data = Arc::new(DATA.to_vec().repeat(512));

//     time::sleep(Duration::from_millis(500)).await;
//     send_and_verify_echo(&connection, &test_data).await?;

//     let paths = connection
//         .paths()?
//         .iter()
//         .map(|path: Arc<qconnection::path::Path>| *path.pathway())
//         .collect::<Vec<_>>();

//     if !paths.iter().any(|p: &Pathway| {
//         matches!(
//             p.local(),
//             EndpointAddr::Socket(SocketEndpointAddr::Direct { .. })
//         )
//     }) {
//         return Err(TestError::NoDirectPath { paths });
//     }
//     tracing::info!("Direct path established: {:?}", paths);
//     Ok(())
// }

// pub type Error = Box<dyn std::error::Error + Send + Sync>;

// #[derive(thiserror::Error, Debug)]
// enum EchoError {
//     #[error(transparent)]
//     Quic(#[from] gm_quic::prelude::Error),
//     #[error(transparent)]
//     StreamIo(#[from] io::Error),
// }

// async fn send_and_verify_echo(connection: &Connection, data: &[u8]) -> Result<(), EchoError> {
//     let (_sid, (mut reader, mut writer)) = connection.open_bi_stream().await?.unwrap();
//     tracing::debug!("stream opened");

//     let mut back = Vec::new();
//     tokio::try_join!(
//         async {
//             writer.write_all(data).await?;
//             writer.shutdown().await?;
//             tracing::info!("write done");
//             Result::<(), EchoError>::Ok(())
//         },
//         async {
//             reader.read_to_end(&mut back).await?;
//             assert_eq!(back, data);
//             tracing::info!("read done");
//             Result::<(), EchoError>::Ok(())
//         }
//     )
//     .map(|_| ())
// }

// async fn serve_echo(server: Arc<QuicListeners>) -> io::Result<()> {
//     loop {
//         let (connection, server, pathway, _link) = server.accept().await.map_err(|e| {
//             tracing::error!(?e, "accept connection failed");
//             io::Error::other("accept error")
//         })?;
//         assert_eq!(server, "localhost");
//         tracing::info!(source = ?pathway.remote(), "accepted new connection");
//         tokio::spawn(async move {
//             while let Ok((_sid, (reader, writer))) = connection.accept_bi_stream().await {
//                 tokio::spawn(echo_stream(reader, writer));
//             }
//         });
//     }
// }

// async fn echo_stream(
//     mut reader: qconnection::StreamReader,
//     mut writer: qconnection::StreamWriter,
// ) -> io::Result<()> {
//     tokio::io::copy(&mut reader, &mut writer).await?;
//     writer.shutdown().await?;
//     tracing::debug!("stream copy done");
//     io::Result::Ok(())
// }

// pub fn server_stream_unlimited_parameters() -> ServerParameters {
//     let mut params = ServerParameters::default();
//     _ = params.set(ParameterId::ActiveConnectionIdLimit, 10u32);
//     _ = params.set(ParameterId::InitialMaxData, 1u32 << 20);
//     _ = params.set(ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 20);
//     _ = params.set(ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 20);
//     _ = params.set(ParameterId::InitialMaxStreamDataUni, 1u32 << 20);
//     _ = params.set(ParameterId::InitialMaxStreamsBidi, 100u32);
//     _ = params.set(ParameterId::InitialMaxStreamsUni, 100u32);
//     params
// }

// fn client_stream_unlimited_parameters() -> ClientParameters {
//     let mut params = ClientParameters::default();
//     _ = params.set(ParameterId::ActiveConnectionIdLimit, 10u32);
//     _ = params.set(ParameterId::InitialMaxData, 1u32 << 20);
//     _ = params.set(ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 20);
//     _ = params.set(ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 20);
//     _ = params.set(ParameterId::InitialMaxStreamDataUni, 1u32 << 20);
//     _ = params.set(ParameterId::InitialMaxStreamsBidi, 100u32);
//     _ = params.set(ParameterId::InitialMaxStreamsUni, 100u32);
//     params
// }

use std::{
    future::Future,
    sync::{Arc, LazyLock, OnceLock},
    time::Duration,
};

use gm_quic::{
    prelude::{handy::*, *},
    qbase,
};
use qbase::param::{ClientParameters, ServerParameters};
use qconnection::qinterface::{logical::BindUri, route::Router};
use qevent::telemetry::QLog;
use rustls::{
    pki_types::{CertificateDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
    time,
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument, level_filters::LevelFilter};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    Layer, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

fn qlogger() -> Arc<dyn QLog + Send + Sync> {
    static QLOGGER: OnceLock<Arc<dyn QLog + Send + Sync>> = OnceLock::new();
    QLOGGER.get_or_init(|| Arc::new(NoopLogger)).clone()
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn run<F: Future>(future: F) -> F::Output {
    static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    });

    static TRACING: LazyLock<WorkerGuard> = LazyLock::new(|| {
        let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());

        tracing_subscriber::registry()
            .with(console_subscriber::spawn())
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(non_blocking)
                    .with_file(true)
                    .with_line_number(true)
                    .with_filter(LevelFilter::DEBUG),
            )
            .with(tracing_subscriber::filter::filter_fn(|metadata| {
                !metadata.target().contains("netlink_packet_route")
            }))
            .init();
        guard
    });

    RT.block_on(async move {
        LazyLock::force(&TRACING);
        match time::timeout(Duration::from_secs(30), future).await {
            Ok(output) => output,
            Err(_timedout) => panic!("test timed out"),
        }
    })
}

fn get_server_addr(listeners: &QuicListeners) -> qbase::net::addr::RealAddr {
    let localhost = listeners
        .get_server("localhost")
        .expect("Server localhost must be registered");
    let localhost_bind_interface = localhost
        .bind_interfaces()
        .into_iter()
        .next()
        .map(|(_bind_uri, interface)| interface)
        .expect("Server should bind at least one address");
    localhost_bind_interface
        .borrow()
        .real_addr()
        .expect("failed to get real addr")
}

const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");
const CLIENT_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/client.cert");
const CLIENT_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/client.key");
const TEST_DATA: &[u8] = include_bytes!("lib.rs");

async fn echo_stream(mut reader: StreamReader, mut writer: StreamWriter) {
    io::copy(&mut reader, &mut writer).await.unwrap();
    _ = writer.shutdown().await;
    tracing::debug!("stream copy done");
}

pub async fn serve_echo(listeners: Arc<QuicListeners>) {
    while let Ok((connection, server, pathway, _link)) = listeners.accept().await {
        assert_eq!(server, "localhost");
        tracing::info!(source = ?pathway.remote(), "accepted new connection");
        tokio::spawn(async move {
            while let Ok((_sid, (reader, writer))) = connection.accept_bi_stream().await {
                tokio::spawn(echo_stream(reader, writer));
            }
        });
    }
}

async fn send_and_verify_echo(connection: &Connection, data: &[u8]) -> Result<(), BoxError> {
    let (_sid, (mut reader, mut writer)) = connection.open_bi_stream().await?.unwrap();
    tracing::debug!("stream opened");

    let mut back = Vec::new();
    tokio::try_join!(
        async {
            writer.write_all(data).await?;
            writer.shutdown().await?;
            tracing::info!("write done");
            Result::<(), BoxError>::Ok(())
        },
        async {
            reader.read_to_end(&mut back).await?;
            assert_eq!(back, data);
            tracing::info!("read done");
            Result::<(), BoxError>::Ok(())
        }
    )
    .map(|_| ())
}

async fn launch_echo_server(
    quic_router: Arc<Router>,
    parameters: ServerParameters,
) -> Result<(Arc<QuicListeners>, impl Future<Output: Send>), BoxError> {
    let listeners = QuicListeners::builder()
        .with_router(quic_router)
        .without_client_cert_verifier()
        .with_parameters(parameters)
        .with_qlog(qlogger())
        .listen(128)
        .unwrap();
    listeners
        .add_server(
            "localhost",
            SERVER_CERT,
            SERVER_KEY,
            [BindUri::from("inet://127.0.0.1:0?alloc_port=true").alloc_port()],
            None,
        )
        .await?;
    Ok((listeners.clone(), serve_echo(listeners)))
}

fn launch_test_client(quic_router: Arc<Router>, parameters: ClientParameters) -> Arc<QuicClient> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap));
    let client = QuicClient::builder()
        .with_router(quic_router)
        .with_root_certificates(roots)
        .with_parameters(parameters)
        .without_cert()
        .with_qlog(qlogger())
        .enable_sslkeylog()
        .build();

    Arc::new(client)
}

#[test]
fn single_stream() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());
        let connection = client.connected_to("localhost", [server_addr]).await?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn signal_big_stream() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());
        let connection = client.connected_to("localhost", [server_addr]).await?;
        send_and_verify_echo(&connection, &TEST_DATA.to_vec().repeat(1024)).await?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn empty_stream() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());
        let connection = client.connected_to("localhost", [server_addr]).await?;
        send_and_verify_echo(&connection, b"").await?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn shutdown() -> Result<(), BoxError> {
    run(async {
        async fn serve_only_one_stream(listeners: Arc<QuicListeners>) {
            while let Ok((connection, server, pathway, _link)) = listeners.accept().await {
                assert_eq!(server, "localhost");
                tracing::info!(source = ?pathway.remote(), "accepted new connection");
                tokio::spawn(async move {
                    let (_sid, (reader, writer)) = connection.accept_bi_stream().await?;
                    echo_stream(reader, writer).await;
                    _ = connection.close("Bye bye", 0);
                    Result::<(), BoxError>::Ok(())
                });
            }
        }

        let router = Arc::new(Router::default());
        let listeners = QuicListeners::builder()
            .with_router(router.clone())
            .without_client_cert_verifier()
            .with_parameters(server_parameters())
            .with_qlog(qlogger())
            .listen(128)?;
        listeners
            .add_server(
                "localhost",
                SERVER_CERT,
                SERVER_KEY,
                [BindUri::from("inet://127.0.0.1:0?alloc_port=true").alloc_port()],
                None,
            )
            .await?;
        let server_task = serve_only_one_stream(listeners.clone());
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);

        let client = launch_test_client(router, client_parameters());
        let connection = client.connected_to("localhost", [server_addr]).await?;
        _ = connection.handshaked().await; // 可有可无

        assert!(
            send_and_verify_echo(&connection, b"").await.is_err()
                || send_and_verify_echo(&connection, b"").await.is_err()
        );

        connection.terminated().await;
        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn idle_timeout() -> Result<(), BoxError> {
    run(async {
        fn server_parameters() -> ServerParameters {
            let mut params = handy::server_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_secs(1))
                .expect("unreachable");

            params
        }

        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);

        let client = launch_test_client(router, client_parameters());
        let connection = client.connected_to("localhost", [server_addr]).await?;
        connection.terminated().await;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn double_connections() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());

        let mut connections = JoinSet::new();

        for conn_idx in 0..2 {
            let connection = client.connected_to("localhost", [server_addr]).await?;
            connections.spawn(
                async move { send_and_verify_echo(&connection, TEST_DATA).await }
                    .instrument(tracing::info_span!("stream", conn_idx)),
            );
        }

        connections
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), BoxError>>()?;

        listeners.shutdown();
        Ok(())
    })
}

const PARALLEL_ECHO_CONNS: usize = 3;
const PARALLEL_ECHO_STREAMS: usize = 2;

#[test]
fn parallel_stream() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());

        let mut streams = JoinSet::new();

        for conn_idx in 0..PARALLEL_ECHO_CONNS {
            tracing::info!(conn_idx, "Starting connection");
            let connection = Arc::new(client.connected_to("localhost", [server_addr]).await?);
            tracing::info!(conn_idx, "Connected");
            for stream_idx in 0..PARALLEL_ECHO_STREAMS {
                let connection = connection.clone();
                streams.spawn(
                    async move { send_and_verify_echo(&connection, TEST_DATA).await }
                        .instrument(tracing::info_span!("stream", conn_idx, stream_idx)),
                );
            }
        }

        streams
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), BoxError>>()?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn parallel_big_stream() -> Result<(), BoxError> {
    run(async {
        fn client_parameters() -> ClientParameters {
            let mut params = handy::client_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_secs(60))
                .expect("unreachable");
            params
        }

        fn server_parameters() -> ServerParameters {
            let mut params = handy::server_parameters();
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_secs(60))
                .expect("unreachable");
            params
        }

        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);

        let client = launch_test_client(router, client_parameters());

        let mut big_streams = JoinSet::new();
        let test_data = Arc::new(TEST_DATA.to_vec().repeat(32));

        for conn_idx in 0..PARALLEL_ECHO_CONNS {
            let connection = client.connected_to("localhost", [server_addr]).await?;
            let test_data = test_data.clone();
            big_streams.spawn(
                async move { send_and_verify_echo(&connection, &test_data).await }
                    .instrument(tracing::info_span!("stream", conn_idx)),
            );
        }

        big_streams
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), BoxError>>()?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn limited_streams() -> Result<(), BoxError> {
    run(async {
        pub fn client_parameters() -> ClientParameters {
            let mut params = ClientParameters::default();

            for (id, value) in [
                (ParameterId::InitialMaxStreamsBidi, 2u32),
                (ParameterId::InitialMaxStreamsUni, 0u32),
                (ParameterId::InitialMaxData, 1u32 << 10),
                (ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 10),
                (ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 10),
                (ParameterId::InitialMaxStreamDataUni, 1u32 << 10),
            ] {
                params.set(id, value).expect("unreachable");
            }

            params
        }

        pub fn server_parameters() -> ServerParameters {
            let mut params = ServerParameters::default();

            for (id, value) in [
                (ParameterId::InitialMaxStreamsBidi, 2u32),
                (ParameterId::InitialMaxStreamsUni, 2u32),
                (ParameterId::InitialMaxData, 1u32 << 20),
                (ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 10),
                (ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 10),
                (ParameterId::InitialMaxStreamDataUni, 1u32 << 10),
            ] {
                params.set(id, value).expect("unreachable");
            }
            params
                .set(ParameterId::MaxIdleTimeout, Duration::from_secs(30))
                .expect("unreachable");

            params
        }

        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);
        let client = launch_test_client(router, client_parameters());

        let mut streams = JoinSet::new();

        for conn_idx in 0..PARALLEL_ECHO_CONNS / 2 {
            let connection = Arc::new(client.connected_to("localhost", [server_addr]).await?);
            for stream_idx in 0..PARALLEL_ECHO_STREAMS / 2 {
                let connection = connection.clone();
                streams.spawn(
                    async move { send_and_verify_echo(&connection, TEST_DATA).await }
                        .instrument(tracing::info_span!("stream", conn_idx, stream_idx)),
                );
            }
        }

        streams
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), BoxError>>()?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn client_without_verify() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_echo_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));

        let server_addr = get_server_addr(&listeners);

        let client = {
            let parameters = client_parameters();
            let client = QuicClient::builder()
                .with_router(router)
                .without_verifier()
                .with_parameters(parameters)
                .without_cert()
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();
            Arc::new(client)
        };

        let connection = client.connected_to("localhost", [server_addr]).await?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        listeners.shutdown();
        Ok(())
    })
}

struct ClientNameAuther<const SILENT_REFUSE: bool>;

impl<const SILENT: bool> AuthClient for ClientNameAuther<SILENT> {
    fn verify_client_name(
        &self,
        _: &LocalAgent,
        client_name: Option<&str>,
    ) -> ClientNameVerifyResult {
        match matches!(client_name, Some("client")) {
            true => ClientNameVerifyResult::Accept,
            false if !SILENT => ClientNameVerifyResult::Refuse("".to_owned()),
            false => ClientNameVerifyResult::SilentRefuse("Client name ".to_owned()),
        }
    }

    fn verify_client_agent(&self, _: &LocalAgent, _: &RemoteAgent) -> ClientAgentVerifyResult {
        ClientAgentVerifyResult::Accept
    }
}

async fn launch_client_auth_test_server<const SILENT_REFUSE: bool>(
    quic_router: Arc<Router>,
    server_parameters: ServerParameters,
) -> Result<(Arc<QuicListeners>, impl Future<Output: Send>), BoxError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap));
    let listeners = QuicListeners::builder()
        .with_router(quic_router)
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
        )
        .with_client_auther(ClientNameAuther::<SILENT_REFUSE>)
        .with_parameters(server_parameters)
        .with_qlog(qlogger())
        .listen(128)?;
    listeners
        .add_server(
            "localhost",
            SERVER_CERT,
            SERVER_KEY,
            [BindUri::from("inet://127.0.0.1:0?alloc_port=true").alloc_port()],
            None,
        )
        .await?;
    Ok((listeners.clone(), serve_echo(listeners)))
}

#[test]
fn auth_client_name() -> Result<(), BoxError> {
    run(async {
        const SILENT_REFUSE: bool = false;

        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_client_auth_test_server::<SILENT_REFUSE>(router.clone(), server_parameters())
                .await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));
        let server_addr = get_server_addr(&listeners);

        let client = {
            let mut parameters = client_parameters();
            _ = parameters.set(ParameterId::ClientName, "client".to_string());

            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_router(router)
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client.connected_to("localhost", [server_addr]).await?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn auth_client_name_incorrect_name() -> Result<(), BoxError> {
    run(async {
        const SILENT_REFUSE: bool = false;

        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_client_auth_test_server::<SILENT_REFUSE>(router.clone(), server_parameters())
                .await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));
        let server_addr = get_server_addr(&listeners);

        let client = {
            let mut parameters = client_parameters();
            _ = parameters.set(ParameterId::ClientName, "another_client".to_string());

            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_router(router)
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client.connected_to("localhost", [server_addr]).await?;
        let error = connection.terminated().await;
        assert_eq!(error.kind(), ErrorKind::ConnectionRefused);

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn auth_client_refuse() -> Result<(), BoxError> {
    run(async {
        const SILENT_REFUSE: bool = false;

        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_client_auth_test_server::<SILENT_REFUSE>(router.clone(), server_parameters())
                .await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));
        let server_addr = get_server_addr(&listeners);

        let client = {
            let parameters = client_parameters();
            // no CLIENT_NAME

            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_router(router)
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client.connected_to("localhost", [server_addr]).await?;

        let error = connection.terminated().await;
        assert_eq!(error.kind(), ErrorKind::ConnectionRefused);

        listeners.shutdown();
        Ok(())
    })
}

#[test]
fn auth_client_refuse_silently() -> Result<(), BoxError> {
    run(async {
        const SILENT_REFUSE: bool = true;

        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_client_auth_test_server::<SILENT_REFUSE>(router.clone(), server_parameters())
                .await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));
        let server_addr = get_server_addr(&listeners);

        let client = {
            let parameters = client_parameters();
            // no CLIENT_NAME

            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_router(router)
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client.connected_to("localhost", [server_addr]).await?;

        assert!(
            time::timeout(Duration::from_secs(3), connection.handshaked())
                .await
                .is_err()
        );

        listeners.shutdown();
        Ok(())
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Message {
    data: Vec<u8>,
    sign: Vec<u8>,
}

const SIGNATURE_SCHEME: rustls::SignatureScheme = rustls::SignatureScheme::ECDSA_NISTP256_SHA256;

async fn send_and_verify_echo_with_sign_verify(
    connection: &Connection,
    data: &[u8],
) -> Result<(), BoxError> {
    let local_agent = connection.local_agent().await.unwrap().unwrap();
    let remote_agent = connection.remote_agent().await.unwrap().unwrap();
    let (_sid, (mut reader, mut writer)) = connection.open_bi_stream().await?.unwrap();
    tracing::debug!("stream opened");

    let write = async {
        let data = data.to_vec();
        let sign = local_agent.sign(SIGNATURE_SCHEME, &data).unwrap();
        let message = postcard::to_stdvec(&Message { data, sign }).unwrap();
        writer.write_all(&message).await?;
        writer.shutdown().await?;
        tracing::info!("write done");
        Result::<(), BoxError>::Ok(())
    };
    let read = async {
        let mut message = Vec::new();
        reader.read_to_end(&mut message).await?;
        let message: Message = postcard::from_bytes(&message).unwrap();
        remote_agent
            .verify(SIGNATURE_SCHEME, &message.data, &message.sign)
            .unwrap();
        assert_eq!(message.data, data);
        tracing::info!("read done");
        Result::<(), BoxError>::Ok(())
    };

    tokio::try_join!(read, write).map(|_| ())
}

async fn echo_stream_with_sign_verify(
    local_agent: LocalAgent,
    remote_agent: RemoteAgent,
    mut reader: StreamReader,
    mut writer: StreamWriter,
) {
    let mut message = Vec::new();
    reader.read_to_end(&mut message).await.unwrap();
    let Message { data, sign } = postcard::from_bytes(&message).unwrap();
    remote_agent.verify(SIGNATURE_SCHEME, &data, &sign).unwrap();
    tracing::debug!("Message received and verified");

    let sign = local_agent.sign(SIGNATURE_SCHEME, &data).unwrap();
    let message = postcard::to_stdvec(&Message { data, sign }).unwrap();
    writer.write_all(&message).await.unwrap();
    writer.shutdown().await.unwrap();
    tracing::debug!("Signed echo sent");
}

pub async fn serve_echo_with_sign_verify(listeners: Arc<QuicListeners>) {
    while let Ok((connection, server, pathway, _link)) = listeners.accept().await {
        assert_eq!(server, "localhost");
        let local_agent = connection.local_agent().await.unwrap().unwrap();
        let remote_agent = connection.remote_agent().await.unwrap().unwrap();
        tracing::info!(source = ?pathway.remote(),"accepted new connection");
        tokio::spawn(async move {
            while let Ok((_sid, (reader, writer))) = connection.accept_bi_stream().await {
                tokio::spawn(echo_stream_with_sign_verify(
                    local_agent.clone(),
                    remote_agent.clone(),
                    reader,
                    writer,
                ));
            }
        });
    }
}

async fn launch_echo_with_sign_verify_server(
    quic_router: Arc<Router>,
    parameters: ServerParameters,
) -> Result<(Arc<QuicListeners>, impl Future<Output: Send>), BoxError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap));
    let listeners = QuicListeners::builder()
        .with_router(quic_router)
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
        )
        .with_parameters(parameters)
        .with_qlog(qlogger())
        .listen(128)?;
    listeners
        .add_server(
            "localhost",
            SERVER_CERT,
            SERVER_KEY,
            [BindUri::from("inet://127.0.0.1:0?alloc_port=true").alloc_port()],
            None,
        )
        .await?;
    Ok((listeners.clone(), serve_echo_with_sign_verify(listeners)))
}

#[test]
fn sign_and_verify() -> Result<(), BoxError> {
    run(async {
        let router = Arc::new(Router::default());
        let (listeners, server_task) =
            launch_echo_with_sign_verify_server(router.clone(), server_parameters()).await?;
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));
        let server_addr = get_server_addr(&listeners);

        let client = {
            let mut parameters = client_parameters();
            _ = parameters.set(ParameterId::ClientName, "client".to_string());

            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_router(router)
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client.connected_to("localhost", [server_addr]).await?;
        send_and_verify_echo_with_sign_verify(&connection, TEST_DATA).await?;

        listeners.shutdown();
        Ok(())
    })
}
