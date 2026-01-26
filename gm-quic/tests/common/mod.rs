// common is submod for both echo and auth tests
#![allow(unused)]

use std::{
    future::Future,
    sync::{Arc, LazyLock, OnceLock},
    time::Duration,
};

use gm_quic::{
    prelude::{handy::*, *},
    qbase::{self, param::ClientParameters},
    qinterface::{component::route::QuicRouter, io::IO},
};
use qevent::telemetry::QLog;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use tokio::time;
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    Layer, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

pub fn qlogger() -> Arc<dyn QLog + Send + Sync> {
    static QLOGGER: OnceLock<Arc<dyn QLog + Send + Sync>> = OnceLock::new();
    QLOGGER.get_or_init(|| Arc::new(NoopLogger)).clone()
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub fn run<F: Future>(future: F) -> F::Output {
    static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    });

    static TRACING: LazyLock<WorkerGuard> = LazyLock::new(|| {
        let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());

        tracing_subscriber::registry()
            // .with(console_subscriber::spawn())
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
        match time::timeout(Duration::from_secs(60), future).await {
            Ok(output) => output,
            Err(_timedout) => panic!("test timed out"),
        }
    })
}

pub fn launch_test_client(
    quic_router: Arc<QuicRouter>,
    parameters: ClientParameters,
) -> Arc<QuicClient> {
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

pub fn get_server_addr(listeners: &QuicListeners) -> qbase::net::addr::RealAddr {
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

pub const CA_CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/ca.cert");
pub const SERVER_CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/server.cert");
pub const SERVER_KEY: &[u8] = include_bytes!("../../../tests/keychain/localhost/server.key");
pub const CLIENT_CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/client.cert");
pub const CLIENT_KEY: &[u8] = include_bytes!("../../../tests/keychain/localhost/client.key");
pub const TEST_DATA: &[u8] = include_bytes!("mod.rs");
