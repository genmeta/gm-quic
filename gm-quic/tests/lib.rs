use std::{
    future::Future,
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use gm_quic::{
    prelude::{
        Connection, EndpointAddr, ParameterId, Pathway, QuicClient, QuicListeners,
        SocketEndpointAddr,
        handy::{LegacySeqLogger, ToCertificate},
    },
    qbase::param::{ClientParameters, ServerParameters},
    qinterface::logical::QuicInterfaces,
    qtraversal::{
        iface::{StunInterface, TraversalFactory},
        nat::{
            StunIO,
            client::{NatType, StunClient},
        },
    },
};
use rustls::RootCertStore;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinError,
    time,
};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone, Copy)]
pub struct TestCase {
    pub bind_addr: &'static str,
    pub outer_addr: &'static str,
    pub nat_type: NatType,
}

pub const STUN_SERVERS: &str = "10.10.0.64:20002";

pub const CASES: [TestCase; 10] = [
    TestCase {
        bind_addr: "192.168.0.98:6001",
        outer_addr: "10.10.0.98:6001",
        nat_type: NatType::FullCone,
    },
    TestCase {
        bind_addr: "192.168.0.96:6002",
        outer_addr: "10.10.0.96:6002",
        nat_type: NatType::RestrictedCone,
    },
    TestCase {
        bind_addr: "192.168.0.88:6003",
        outer_addr: "10.10.0.88:6003",
        nat_type: NatType::RestrictedPort,
    },
    TestCase {
        bind_addr: "192.168.0.86:6004",
        outer_addr: "10.10.0.86:6004",
        nat_type: NatType::Dynamic,
    },
    TestCase {
        bind_addr: "192.168.0.84:6005",
        outer_addr: "10.10.0.84:6005",
        nat_type: NatType::Symmetric,
    },
    TestCase {
        bind_addr: "172.16.0.48:6006",
        outer_addr: "10.10.0.48:6006",
        nat_type: NatType::FullCone,
    },
    TestCase {
        bind_addr: "172.16.0.46:6007",
        outer_addr: "10.10.0.46:6007",
        nat_type: NatType::RestrictedCone,
    },
    TestCase {
        bind_addr: "172.16.0.38:6008",
        outer_addr: "10.10.0.38:6008",
        nat_type: NatType::RestrictedPort,
    },
    TestCase {
        bind_addr: "172.16.0.36:6009",
        outer_addr: "10.10.0.36:6009",
        nat_type: NatType::Dynamic,
    },
    TestCase {
        bind_addr: "172.16.0.34:6010",
        outer_addr: "10.10.0.34:6010",
        nat_type: NatType::Symmetric,
    },
];

pub fn init_logger() -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("test.log")?;

    let filter = tracing_subscriber::filter::filter_fn(|metadata| {
        !metadata.target().contains("netlink_packet_route")
    });

    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::Layer::with_filter(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_ansi(false)
                .with_file(true)
                .with_line_number(true),
            filter.clone(),
        ))
        .with(tracing_subscriber::Layer::with_filter(
            tracing_subscriber::fmt::layer().with_writer(file),
            filter,
        ))
        .try_init();
    Ok(())
}

fn run<T: Send + 'static>(
    future: impl Future<Output = T> + Send + 'static,
) -> Result<T, JoinError> {
    static RT: OnceLock<Mutex<tokio::runtime::Runtime>> = OnceLock::new();
    let rt = RT.get_or_init(|| {
        Mutex::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        )
    });
    rt.lock()
        .unwrap()
        .block_on(async move { tokio::spawn(future).await })
}

async fn test_detect_case(case: usize) {
    init_logger().unwrap();
    let stun = STUN_SERVERS.parse().unwrap();
    let case = CASES[case];
    let socket_addr: SocketAddr = case.bind_addr.parse::<SocketAddr>().unwrap();
    let bind_uri = format!("inet://{}", case.bind_addr);
    let iface = Arc::new(StunInterface::new(socket_addr, bind_uri.into()).unwrap());
    let client = StunClient::new(iface.stun_protocol().unwrap(), stun);
    let outer_addr = client.outer_addr().await.expect("failed to get outer addr");
    info!("Outer addr: {} Agent addr {}", outer_addr, stun);
    let nat_type = client.nat_type().await.expect("failed to get nat type");
    info!(
        "bind addr: {} outer addr: {} NAT type: {:?} expected: {:?}",
        case.bind_addr, case.outer_addr, nat_type, case.nat_type
    );
    assert!(nat_type == case.nat_type);
}

macro_rules! test_detect {
    (async fn $test_name:ident = test_detect_case($case:expr) $($tt:tt)*) => {

        #[test]
        #[ignore]
        fn $test_name() -> Result<(), JoinError> {
            run(async move {
                test_detect_case($case).await
            })
        }

        test_detect!($($tt)*);
    };
    () => {}
}

// ip netns exec nsa cargo test --package gm-quic test_detect -- --nocapture
test_detect! {
    async fn test_detect_full_cone_client = test_detect_case(0)
    async fn test_detect_restricted_cone_client = test_detect_case(1)
    async fn test_detect_port_restricted_client = test_detect_case(2)
    async fn test_detect_dynamic_client = test_detect_case(3)
    async fn test_detect_symmetric_client = test_detect_case(4)
    async fn test_detect_full_cone_server = test_detect_case(5)
    async fn test_detect_restricted_cone_server = test_detect_case(6)
    async fn test_detect_port_restricted_server = test_detect_case(7)
    async fn test_detect_dynamic_server = test_detect_case(8)
    async fn test_detect_symmetric_server = test_detect_case(9)
}

const CLIENT_ADDR: [TestCase; 5] = [
    CASES[0], // Full cone
    CASES[1], // Restricted cone
    CASES[2], // Port restricted
    CASES[3], // Dynamic
    CASES[4], // Symmetric
];

const SERVER_ADDR: [TestCase; 5] = [
    CASES[5], // Full cone
    CASES[6], // Restricted cone
    CASES[7], // Port restricted
    CASES[8], // Dynamic
    CASES[9], // Symmetric
];

macro_rules! test_punch_pair {
    (async fn $test_name:ident = test_punch_case($client:expr, $server:expr) $($tt:tt)*) => {

        #[test]
        #[ignore]
        fn $test_name() -> Result<Result<(), TestError>, JoinError> {
            run(async move {
                test_punch_case($client, $server).await
            })
        }

        test_punch_pair!($($tt)*);
    };
    () => {}
}

// ip netns exec nsa cargo test --package gm-quic test_punch -- --nocapture
test_punch_pair! {
    async fn test_punch_full_cone_to_full_cone = test_punch_case(0, 0)
    async fn test_punch_full_cone_to_restricted_cone = test_punch_case(0, 1)
    async fn test_punch_full_cone_to_port_restricted = test_punch_case(0, 2)
    async fn test_punch_full_cone_to_dynamic = test_punch_case(0, 3)
    async fn test_punch_full_cone_to_symmetric = test_punch_case(0, 4)
    async fn test_punch_restricted_cone_to_full_cone = test_punch_case(1, 0)
    async fn test_punch_restricted_cone_to_restricted_cone = test_punch_case(1, 1)
    async fn test_punch_restricted_cone_to_port_restricted = test_punch_case(1, 2)
    async fn test_punch_restricted_cone_to_dynamic = test_punch_case(1, 3)
    async fn test_punch_restricted_cone_to_symmetric = test_punch_case(1, 4)
    async fn test_punch_port_restricted_to_full_cone = test_punch_case(2, 0)
    async fn test_punch_port_restricted_to_restricted_cone = test_punch_case(2, 1)
    async fn test_punch_port_restricted_to_port_restricted = test_punch_case(2, 2)
    async fn test_punch_port_restricted_to_dynamic = test_punch_case(2, 3)
     async fn test_punch_port_restricted_to_symmetric = test_punch_case(2, 4)
    async fn test_punch_dynamic_to_full_cone = test_punch_case(3, 0)
    async fn test_punch_dynamic_to_restricted_cone = test_punch_case(3, 1)
    async fn test_punch_dynamic_to_port_restricted = test_punch_case(3, 2)
    async fn test_punch_dynamic_to_dynamic = test_punch_case(3, 3)
    async fn test_punch_dynamic_to_symmetric = test_punch_case(3, 4)
    async fn test_punch_symmetric_to_full_cone = test_punch_case(4, 0)
    async fn test_punch_symmetric_to_restricted_cone = test_punch_case(4, 1)
    async fn test_punch_symmetric_to_port_restricted = test_punch_case(4, 2)
    async fn test_punch_symmetric_to_dynamic = test_punch_case(4, 3)
    async fn test_punch_symmetric_to_symmetric = test_punch_case(4, 4)
}

// #[tokio::test]
// async fn test_punch() -> io::Result<()> {
//     init_logger().unwrap();
//     for (client, server) in (0..CLIENT_ADDR.len())
//         .flat_map(|client| (0..SERVER_ADDR.len()).map(move |server| (client, server)))
//     {
//         info!(
//             "Testing punch case: client {} ({:?}) <-> server {} ({:?})",
//             client, CLIENT_ADDR[client].nat_type, server, SERVER_ADDR[server].nat_type
//         );
//         test_punch_case(client, server).await.unwrap();
//     }
//     Ok(())
// }

pub const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
pub const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
pub const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

#[derive(thiserror::Error, Debug)]
enum TestError {
    #[error("operation timed out after {duration:?}")]
    Timeout { duration: Duration },
    #[error("Echo failed")]
    Echo {
        #[from]
        source: EchoError,
    },
    #[error("Quic connection failed")]
    Connection {
        #[from]
        source: gm_quic::prelude::Error,
    },
    #[error("No direct path established, paths: {paths:?}")]
    NoDirectPath { paths: Vec<Pathway> },

    #[error("Failed to get endpoint address")]
    GetEndpointAddr {
        #[from]
        source: io::Error,
    },
}

async fn test_punch_case(client: usize, server: usize) -> Result<(), TestError> {
    init_logger().unwrap();

    info!(
        "Testing punch case: client {} ({:?}) <-> server {} ({:?})",
        client, CLIENT_ADDR[client].nat_type, server, SERVER_ADDR[server].nat_type
    );

    if client == 3 || server == 3 {
        warn!("Skipping Dynamic NAT test case");
        // Dynamic NAT 模拟有问题
        return Ok(());
    }
    if client == 4 && server == 4 {
        warn!("Skipping Symmetric NAT to Symmetric NAT test case");
        // Symmetric NAT 互穿不通
        return Ok(());
    }

    let stun = STUN_SERVERS.parse().unwrap();
    let client_addr: SocketAddr = CLIENT_ADDR[client].bind_addr.parse().unwrap();
    let server_addr: SocketAddr = SERVER_ADDR[server].bind_addr.parse().unwrap();

    let factory = TraversalFactory::initialize_global([stun].to_vec()).unwrap();
    let server = QuicListeners::builder()
        .unwrap()
        .with_qlog(Arc::new(LegacySeqLogger::new(PathBuf::from("./"))))
        .with_iface_factory(factory.as_ref().clone())
        .with_parameters(server_stream_unlimited_parameters())
        .without_client_cert_verifier()
        .listen(1000);

    server
        .add_server("localhost", SERVER_CERT, SERVER_KEY, [server_addr], None)
        .await
        .unwrap();

    tokio::spawn(serve_echo(server.clone()));
    let server_iface = QuicInterfaces::global()
        .borrow(&(server_addr.into()))
        .unwrap();
    info!("Server listening on {server_addr}");

    let server_ep = std::future::poll_fn(|cx| server_iface.poll_endpoint_addr(cx)).await?;
    let launch_client = launch_client(client_addr, EndpointAddr::Socket(server_ep));
    let duration = Duration::from_secs(10);
    let result = time::timeout(duration, launch_client)
        .await
        .map_err(|_| TestError::Timeout { duration });

    server.shutdown();

    result?
}

async fn launch_client(client_addr: SocketAddr, server_ep: EndpointAddr) -> Result<(), TestError> {
    let stun = STUN_SERVERS.parse().unwrap();
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(CA_CERT.to_certificate());

    let factory = TraversalFactory::initialize_global([stun].to_vec()).unwrap();
    let client = QuicClient::builder()
        .with_root_certificates(roots)
        .without_cert()
        .enable_sslkeylog()
        .with_qlog(Arc::new(LegacySeqLogger::new(PathBuf::from("./"))))
        .with_iface_factory(factory.as_ref().clone())
        .with_parameters(client_stream_unlimited_parameters())
        .bind([client_addr])
        .await
        .build();

    // 不会进行绑定，不会出错
    let connection = client.connected_to("localhost", [server_ep]).await.unwrap();
    const DATA: &[u8] = include_bytes!("./lib.rs");
    let test_data = Arc::new(DATA.to_vec().repeat(512));

    time::sleep(Duration::from_millis(500)).await;
    send_and_verify_echo(&connection, &test_data).await?;

    let paths = connection
        .paths()?
        .iter()
        .map(|path: Arc<qconnection::path::Path>| *path.pathway())
        .collect::<Vec<_>>();

    if !paths.iter().any(|p: &Pathway| {
        matches!(
            p.local(),
            EndpointAddr::Socket(SocketEndpointAddr::Direct { .. })
        )
    }) {
        return Err(TestError::NoDirectPath { paths });
    }
    tracing::info!("Direct path established: {:?}", paths);
    Ok(())
}

pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(thiserror::Error, Debug)]
enum EchoError {
    #[error(transparent)]
    Quic(#[from] gm_quic::prelude::Error),
    #[error(transparent)]
    StreamIo(#[from] io::Error),
}

async fn send_and_verify_echo(connection: &Connection, data: &[u8]) -> Result<(), EchoError> {
    let (_sid, (mut reader, mut writer)) = connection.open_bi_stream().await?.unwrap();
    tracing::debug!("stream opened");

    let mut back = Vec::new();
    tokio::try_join!(
        async {
            writer.write_all(data).await?;
            writer.shutdown().await?;
            tracing::info!("write done");
            Result::<(), EchoError>::Ok(())
        },
        async {
            reader.read_to_end(&mut back).await?;
            assert_eq!(back, data);
            tracing::info!("read done");
            Result::<(), EchoError>::Ok(())
        }
    )
    .map(|_| ())
}

async fn serve_echo(server: Arc<QuicListeners>) -> io::Result<()> {
    loop {
        let (connection, server, pathway, _link) = server.accept().await.map_err(|e| {
            tracing::error!(?e, "accept connection failed");
            io::Error::other("accept error")
        })?;
        assert_eq!(server, "localhost");
        tracing::info!(source = ?pathway.remote(), "accepted new connection");
        tokio::spawn(async move {
            while let Ok((_sid, (reader, writer))) = connection.accept_bi_stream().await {
                tokio::spawn(echo_stream(reader, writer));
            }
        });
    }
}

async fn echo_stream(
    mut reader: qconnection::StreamReader,
    mut writer: qconnection::StreamWriter,
) -> io::Result<()> {
    tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    tracing::debug!("stream copy done");
    io::Result::Ok(())
}

pub fn server_stream_unlimited_parameters() -> ServerParameters {
    let mut params = ServerParameters::default();
    _ = params.set(ParameterId::ActiveConnectionIdLimit, 10u32);
    _ = params.set(ParameterId::InitialMaxData, 1u32 << 20);
    _ = params.set(ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 20);
    _ = params.set(ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 20);
    _ = params.set(ParameterId::InitialMaxStreamDataUni, 1u32 << 20);
    _ = params.set(ParameterId::InitialMaxStreamsBidi, 100u32);
    _ = params.set(ParameterId::InitialMaxStreamsUni, 100u32);
    params
}

fn client_stream_unlimited_parameters() -> ClientParameters {
    let mut params = ClientParameters::default();
    _ = params.set(ParameterId::ActiveConnectionIdLimit, 10u32);
    _ = params.set(ParameterId::InitialMaxData, 1u32 << 20);
    _ = params.set(ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 20);
    _ = params.set(ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 20);
    _ = params.set(ParameterId::InitialMaxStreamDataUni, 1u32 << 20);
    _ = params.set(ParameterId::InitialMaxStreamsBidi, 100u32);
    _ = params.set(ParameterId::InitialMaxStreamsUni, 100u32);
    params
}
