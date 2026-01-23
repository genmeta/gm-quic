use std::{
    io,
    net::SocketAddr,
    sync::{Arc, LazyLock},
};

use futures::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use gm_quic::{
    prelude::{handy::*, *},
    qinterface::manager::InterfaceManager,
    qtraversal::nat::client::{NatType, StunClientsComponent},
};
use rustls::RootCertStore;
use tokio::task::JoinSet;
use tracing::{info, warn};

mod common;
use common::*;
mod echo_common;
use echo_common::*;

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
    // server
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
        fn $test_name() {
            run(async move {
                test_punch_case($client, $server).await
            });
        }

        test_punch_pair!($($tt)*);
    };
    () => {}
}

/*
    // in host:
    sudo docker buildx build -f qtraversal/tools/dockerfile -t gm-quic-traversal-test:latest .
    sudo docker run -it --rm --privileged -v .:/gm-quic gm-quic-traversal-test:latest

    // in contrainer:
    cd /gm-quic && ./qtraversal/tools/run_stun.sh
    ip netns exec nsa cargo test --test traversal -- --include-ignored --nocapture
*/

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

async fn launch_stun_test_server(server: usize) -> Arc<QuicListeners> {
    let server_addr: SocketAddr = SERVER_ADDR[server].bind_addr.parse().unwrap();
    let listeners = QuicListeners::builder()
        .with_parameters(server_parameters())
        .without_client_cert_verifier()
        .with_stun(STUN_SERVERS)
        .with_router(Arc::default())
        .with_qlog(qlogger())
        .listen(1000)
        .unwrap();

    listeners
        .add_server("localhost", SERVER_CERT, SERVER_KEY, [server_addr], None)
        .await
        .unwrap();

    info!("Server listening on {server_addr}");

    tokio::spawn(serve_echo(listeners.clone()));

    listeners
}

static SERVERS: [LazyLock<Shared<BoxFuture<Arc<QuicListeners>>>>; 5] = [
    LazyLock::new(|| launch_stun_test_server(0).boxed().shared()),
    LazyLock::new(|| launch_stun_test_server(1).boxed().shared()),
    LazyLock::new(|| launch_stun_test_server(2).boxed().shared()),
    LazyLock::new(|| launch_stun_test_server(3).boxed().shared()),
    LazyLock::new(|| launch_stun_test_server(4).boxed().shared()),
];

async fn test_punch_case(client: usize, server: usize) {
    info!(
        "Testing punch case: client {} ({:?}) <-> server {} ({:?})",
        client, CLIENT_ADDR[client].nat_type, server, SERVER_ADDR[server].nat_type
    );

    if client == 3 || server == 3 {
        warn!("Skipping Dynamic NAT test case");
        // TODO: Dynamic NAT 模拟有问题
        return;
    }
    if client == 4 && server == 4 {
        warn!("Skipping Symmetric NAT to Symmetric NAT test case");
        // Symmetric NAT 互穿不通
        return;
    }

    let client_addr: SocketAddr = CLIENT_ADDR[client].bind_addr.parse().unwrap();
    let server_addr: SocketAddr = SERVER_ADDR[server].bind_addr.parse().unwrap();

    let _server = SERVERS[server].clone().await;
    let server_iface = InterfaceManager::global()
        .borrow(&(server_addr.into()))
        .unwrap();

    let server_ep = get_stun_data(server_iface).await[0].0;
    launch_client(client_addr, EndpointAddr::Socket(server_ep)).await;
}

async fn get_stun_data(
    server_iface: gm_quic::qinterface::Interface,
) -> Vec<(SocketEndpointAddr, NatType)> {
    let mut outer_addresses = server_iface
        .with_component(|clients: &StunClientsComponent| {
            clients.with_clients(|clients| {
                // workaround. clippy issue: https://github.com/rust-lang/rust-clippy/issues/16428
                #[allow(clippy::redundant_iter_cloned)]
                clients
                    .values()
                    .cloned()
                    .map(|client| async move {
                        let agent = client.agent_addr();
                        let outer = client.outer_addr().await?;
                        let ep = SocketEndpointAddr::with_agent(agent, outer);
                        let nat_type = client.nat_type().await?;
                        io::Result::Ok((ep, nat_type))
                    })
                    .collect::<JoinSet<_>>()
            })
        })
        .expect("interface rebinded too quickly")
        .expect("traversal components missing");
    let mut datas = vec![];

    while let Some(join_result) = outer_addresses.join_next().await {
        let result = join_result.expect("detect panic");
        let data = result.expect("detect outer addr or nat type failed");
        datas.push(data);
    }
    datas
}

async fn launch_client(client_addr: SocketAddr, server_ep: EndpointAddr) {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(CA_CERT.to_certificate());

    let client = QuicClient::builder()
        .with_root_certificates(roots)
        .without_cert()
        .enable_sslkeylog()
        .with_parameters(client_parameters())
        .with_stun(STUN_SERVERS)
        .bind([client_addr])
        .await
        .with_qlog(qlogger())
        .build();

    get_stun_data(
        InterfaceManager::global()
            .borrow(&client_addr.into())
            .unwrap(),
    )
    .await;

    // 不会进行绑定，不会出错
    let connection = client.connected_to("localhost", [server_ep]).await.unwrap();
    let odcid = connection.origin_dcid().expect("connection failed");
    tracing::info!(%odcid, "conneced to server");
    let test_data = Arc::new(TEST_DATA.to_vec());

    send_and_verify_echo(&connection, &test_data)
        .await
        .expect("echo test failed");

    let paths = connection
        .path_context()
        .expect("conenction failed")
        .paths::<Vec<_>>()
        .into_iter()
        .map(|(p, _)| p)
        .collect::<Vec<_>>();

    let has_direct = paths.iter().any(|pathway| {
        matches!(
            pathway.local(),
            EndpointAddr::Socket(SocketEndpointAddr::Direct { .. })
        )
    });

    assert!(has_direct, "No direct path established: {:?}", paths);
    tracing::info!("Direct path established: {:?}", paths);
}

pub type Error = Box<dyn std::error::Error + Send + Sync>;
