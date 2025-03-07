mod echo_server {
    use crate as gm_quic;
    include!("../examples/echo_server.rs");
}

fn client_stream_unlimited_parameters() -> crate::ClientParameters {
    let mut params = crate::ClientParameters::default();

    params.set_initial_max_streams_bidi(100);
    params.set_initial_max_streams_uni(100);
    params.set_initial_max_data((1u32 << 20).into());
    params.set_initial_max_stream_data_uni((1u32 << 20).into());
    params.set_initial_max_stream_data_bidi_local((1u32 << 20).into());
    params.set_initial_max_stream_data_bidi_remote((1u32 << 20).into());

    params
}

use std::{
    io,
    sync::{Arc, LazyLock},
    time::Duration,
};

use echo_server::server_stream_unlimited_parameters;
use qlog::telemetry::{Log, handy::*};
use rustls::RootCertStore;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};
use tracing::{debug, error, info, info_span};

use crate::ToCertificate;

static LOGGER: LazyLock<Arc<dyn Log + Send + Sync>> = LazyLock::new(|| {
    // Arc::new(DefaultSeqLogger::new(std::path::PathBuf::from("/tmp")))
    Arc::new(NullLogger)
});

#[tokio::test]
async fn set() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::INFO)
        // .with_max_level(tracing::level_filters::LevelFilter::TRACE)
        // .with_writer(
        //     std::fs::OpenOptions::new()
        //         .create(true)
        //         .write(true)
        //         .truncate(true)
        //         .open("/tmp/gm-quic.log")?,
        // )
        // .with_ansi(false)
        .init();

    disable_keep_alive().await;
    enable_keep_alive().await;
    parallel_stream().await?;
    limited_streams().await?;

    Ok(())
}

async fn parallel_stream() -> io::Result<()> {
    let server = crate::QuicServer::builder()
        .without_cert_verifier()
        .with_single_cert(
            include_bytes!("../examples/keychain/localhost/server.cert"),
            include_bytes!("../examples/keychain/localhost/server.key"),
        )
        .with_parameters(server_stream_unlimited_parameters())
        .with_qlog(LOGGER.clone())
        .listen("0.0.0.0:0")?;

    let mut server_addr = server.addresses().into_iter().next().unwrap();
    server_addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    tokio::spawn(echo_server::launch(server.clone()));

    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(
        include_bytes!("../examples/keychain/localhost/ca.cert").to_certificate(),
    );

    let client = Arc::new(
        crate::QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .with_parameters(client_stream_unlimited_parameters())
            .with_qlog(LOGGER.clone())
            .build(),
    );

    const CONNECTIONS: usize = 2;
    const STREAMS: usize = 16;
    const DATA: &[u8] = include_bytes!("tests.rs");

    let mut connections = JoinSet::new();

    async fn for_each_connection(connection: Arc<crate::Connection>) -> io::Result<()> {
        let mut streams = JoinSet::new();
        for stream_idx in 0..STREAMS {
            streams.spawn({
                let connection = connection.clone();
                tracing::Instrument::instrument(
                    async move {
                        let (stream_id, (mut reader, mut writer)) =
                            connection.open_bi_stream().await?.unwrap();
                        debug!(%stream_id, "opened stream");

                        writer.write_all(DATA).await?;
                        writer.shutdown().await?;
                        debug!(%stream_id, "sender shutdowned, wait for server to echo");

                        let mut data = Vec::new();
                        reader.read_to_end(&mut data).await?;

                        if data != DATA {
                            error!("server incorrectly echoed");
                            return Err(io::Error::other("server incorrectly echoed"));
                        }

                        info!(%stream_id, "server correctly echoed");

                        io::Result::Ok(())
                    },
                    info_span!("stream", stream_idx),
                )
            });
        }

        streams.join_all().await.into_iter().collect()
    }

    for conn_idx in 0..CONNECTIONS {
        connections.spawn({
            let client = client.clone();
            tracing::Instrument::instrument(
                async move {
                    let connection = client.connect("localhost", server_addr)?;
                    for_each_connection(connection).await
                },
                info_span!("connection", conn_idx),
            )
        });
    }

    connections
        .join_all()
        .await
        .into_iter()
        .collect::<Result<(), _>>()?;
    server.shutdown();
    Ok(())
}

async fn limited_streams() -> io::Result<()> {
    fn client_stream_limited_parameters() -> crate::ClientParameters {
        let mut params = crate::ClientParameters::default();

        params.set_initial_max_streams_bidi(2);
        params.set_initial_max_streams_uni(0);
        params.set_initial_max_data((1u32 << 10).into());
        params.set_initial_max_stream_data_uni((1u32 << 10).into());
        params.set_initial_max_stream_data_bidi_local((1u32 << 10).into());
        params.set_initial_max_stream_data_bidi_remote((1u32 << 10).into());

        params
    }

    fn server_stream_limited_parameters() -> crate::ServerParameters {
        let mut params = crate::ServerParameters::default();

        params.set_initial_max_streams_bidi(2);
        params.set_initial_max_streams_uni(0);
        params.set_initial_max_data((1u32 << 10).into());
        params.set_initial_max_stream_data_uni((1u32 << 10).into());
        params.set_initial_max_stream_data_bidi_local((1u32 << 10).into());
        params.set_initial_max_stream_data_bidi_remote((1u32 << 10).into());

        params
    }

    let server = crate::QuicServer::builder()
        .without_cert_verifier()
        .with_single_cert(
            include_bytes!("../examples/keychain/localhost/server.cert"),
            include_bytes!("../examples/keychain/localhost/server.key"),
        )
        .with_parameters(server_stream_limited_parameters())
        .with_qlog(LOGGER.clone())
        .listen("0.0.0.0:0")?;

    let mut server_addr = server.addresses().into_iter().next().unwrap();
    server_addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    tokio::spawn(echo_server::launch(server.clone()));

    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(
        include_bytes!("../examples/keychain/localhost/ca.cert").to_certificate(),
    );

    let client = Arc::new(
        crate::QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .with_parameters(client_stream_limited_parameters())
            .with_qlog(LOGGER.clone())
            .build(),
    );

    const STREAMS: usize = 4;
    const DATA: &[u8] = include_bytes!("tests.rs");

    let connection = info_span!("client").in_scope(|| client.connect("localhost", server_addr))?;
    let mut streams = JoinSet::new();

    for stream_idx in 0..STREAMS {
        let (sid, (mut reader, mut writer)) = connection.open_bi_stream().await?.unwrap();
        streams.spawn(tracing::Instrument::instrument(
            async move {
                debug!(%sid, "opened stream");

                writer.write_all(DATA).await?;
                writer.shutdown().await?;
                debug!(%sid, "sender shutdowned, wait for server to echo");

                let mut data = Vec::new();
                reader.read_to_end(&mut data).await?;

                if data != DATA {
                    error!("server incorrectly echoed");
                    return Err(io::Error::other("server incorrectly echoed"));
                }

                info!(%sid, "server correctly echoed");

                io::Result::Ok(())
            },
            info_span!("stream", stream_idx),
        ));
    }

    streams
        .join_all()
        .await
        .into_iter()
        .collect::<Result<(), _>>()?;
    connection.close("done".into(), 0);

    server.shutdown();
    Ok(())
}

async fn disable_keep_alive() {
    let disabled_keep_alive = crate::HeartbeatConfig::disabled();

    let mut parameters = crate::ServerParameters::default();
    parameters.set_max_idle_timeout(Duration::from_millis(500));

    let server = crate::QuicServer::builder()
        .without_cert_verifier()
        .with_single_cert(
            include_bytes!("../examples/keychain/localhost/server.cert"),
            include_bytes!("../examples/keychain/localhost/server.key"),
        )
        .defer_idle_timeout(disabled_keep_alive)
        .with_parameters(parameters)
        .with_qlog(LOGGER.clone())
        .listen("127.0.0.1:0")
        .unwrap();
    let mut server_addr = server.addresses().into_iter().next().unwrap();
    server_addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());

    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(
        include_bytes!("../examples/keychain/localhost/ca.cert").to_certificate(),
    );
    let client = Arc::new(
        crate::QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .defer_idle_timeout(disabled_keep_alive)
            .with_qlog(LOGGER.clone())
            .build(),
    );

    let connection = client.connect("localhost", server_addr).unwrap();

    // timeout after 0.5s
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!connection.is_active());
    server.shutdown();
}

async fn enable_keep_alive() {
    let enabled_keep_alive = crate::HeartbeatConfig::new_with_interval(
        Duration::from_millis(2000),
        Duration::from_millis(100),
    );

    let mut parameters = crate::ServerParameters::default();
    parameters.set_max_idle_timeout(Duration::from_millis(500));

    let server = crate::QuicServer::builder()
        .without_cert_verifier()
        .with_single_cert(
            include_bytes!("../examples/keychain/localhost/server.cert"),
            include_bytes!("../examples/keychain/localhost/server.key"),
        )
        .with_parameters(parameters)
        .with_qlog(LOGGER.clone())
        .listen("127.0.0.1:0")
        .unwrap();
    let mut server_addr = server.addresses().into_iter().next().unwrap();
    server_addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());

    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(
        include_bytes!("../examples/keychain/localhost/ca.cert").to_certificate(),
    );
    let client = Arc::new(
        crate::QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .defer_idle_timeout(enabled_keep_alive)
            .with_qlog(LOGGER.clone())
            .build(),
    );

    let connection = client.connect("localhost", server_addr).unwrap();

    // timeout after 0.5s, but keep alive for 2s with 100ms interval
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(connection.is_active());
    server.shutdown();
}
