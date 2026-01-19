use std::{
    io,
    sync::{Arc, LazyLock},
};

use qinterface::{
    Interface,
    factory::{ProductInterface, handy::DEFAULT_QUIC_IO_FACTORY},
};
use qtraversal::{
    nat::{
        client::{NatType, StunClient},
        router::StunRouter,
    },
    route::ReceiveAndDeliverPacket,
};
use tracing::{Instrument, info_span};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone, Copy)]
pub struct TestCase {
    pub bind_addr: &'static str,
    pub outer_addr: &'static str,
    pub nat_type: NatType,
}

pub const STUN_AGENT: &str = "10.10.0.64:20002";

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

pub fn init_tracing() -> io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("tests.log")?;

    let filter = tracing_subscriber::filter::filter_fn(|metadata| {
        !metadata.target().contains("netlink_packet_route")
    });

    _ = tracing_subscriber::registry()
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

fn run<F: Future<Output: Send + 'static> + Send + 'static>(
    test_name: &'static str,
    f: F,
) -> F::Output {
    static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        init_tracing().expect("failed to init tracing");
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    });
    RT.block_on(f.instrument(info_span!("test", test_name)))
}

async fn test_detect_case(case: usize) {
    let stun_agent = STUN_AGENT.parse().unwrap();
    let case = CASES[case];
    let bind_uri = format!("inet://{}", case.bind_addr);
    let iface: Arc<dyn Interface> = Arc::from(DEFAULT_QUIC_IO_FACTORY.bind(bind_uri.into()));
    let stun_router = StunRouter::new();
    let stun_client = StunClient::new(iface.clone(), stun_router.clone(), stun_agent);

    let _route_task = ReceiveAndDeliverPacket::task()
        .stun_routers(stun_router)
        .iface_ref(iface.clone())
        .spawn();

    let outer_addr = stun_client
        .outer_addr()
        .await
        .expect("failed to get outer addr");
    tracing::info!("Outer addr: {} Agent addr {}", outer_addr, stun_agent);
    let nat_type = stun_client
        .nat_type()
        .await
        .expect("failed to get nat type");
    tracing::info!(case.bind_addr, case.outer_addr, ?nat_type, ?case.nat_type);
    assert!(nat_type == case.nat_type);
}

macro_rules! test_detect {
    (async fn $test_name:ident = test_detect_case($case:expr) $($tt:tt)*) => {

        #[test]
        fn $test_name() {
            run(stringify!($test_name), async move {
                test_detect_case($case).await
            })
        }

        test_detect!($($tt)*);
    };
    () => {}
}

// ip netns exec nsa cargo test --package qtraversal test_detect -- --nocapture
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
