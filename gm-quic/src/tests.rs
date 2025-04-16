use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, Once},
    time::Duration,
};

use qevent::telemetry::{Log, handy::*};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    runtime::Runtime,
    sync::Mutex,
    task::JoinSet,
    time,
};
use tracing::Instrument;

use crate::{handy::*, *};

fn qlogger() -> Arc<dyn Log + Send + Sync> {
    static QLOGGER: OnceLock<Arc<dyn Log + Send + Sync>> = OnceLock::new();
    QLOGGER.get_or_init(|| Arc::new(NullLogger)).clone()
}

pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub fn run_serially<C, S>(
    launch_server: impl FnOnce() -> Result<(Arc<QuicServer>, S), Error>,
    launch_client: impl FnOnce(SocketAddr) -> C,
) -> Result<(), Error>
where
    C: Future<Output = Result<(), Error>> + 'static,
    S: Future<Output: Send> + Send + 'static,
{
    static SUBSCRIBER: Once = Once::new();

    SUBSCRIBER.call_once(|| {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init()
    });

    static RT: OnceLock<Runtime> = OnceLock::new();

    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create runtime")
    });

    rt.block_on(async move {
        static LOCK: OnceLock<Arc<Mutex<()>>> = OnceLock::new();
        let _lock = LOCK.get_or_init(Default::default).lock().await;

        let (server, server_task) = launch_server()?;
        let server_task = tokio::task::spawn(server_task);
        let server_addr = *server.addresses().iter().next().expect("no address");
        time::timeout(Duration::from_secs(10), launch_client(server_addr))
            .await
            .expect("test timeout")?;
        server.shutdown();
        server_task.abort();
        Ok(())
    })
}

async fn echo_stream(mut reader: StreamReader, mut writer: StreamWriter) -> io::Result<()> {
    io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    tracing::debug!("stream copy done");

    io::Result::Ok(())
}

pub async fn serve_echo(server: Arc<QuicServer>) -> io::Result<()> {
    loop {
        let (connection, pathway) = server.accept().await?;
        tracing::info!(source = ?pathway.remote(), "accepted new connection");
        tokio::spawn(async move {
            while let Ok(Some((_sid, (reader, writer)))) = connection.accept_bi_stream().await {
                tokio::spawn(echo_stream(reader, writer));
            }
        });
    }
}

async fn send_and_verify_echo(connection: &Connection, data: &[u8]) -> Result<(), Error> {
    let (_sid, (mut reader, mut writer)) = connection.open_bi_stream().await?.unwrap();
    tracing::debug!("stream opened");

    let mut back = Vec::new();
    tokio::try_join!(
        async {
            writer.write_all(data).await?;
            writer.shutdown().await?;
            tracing::debug!("write done");
            Result::<(), Error>::Ok(())
        },
        async {
            reader.read_to_end(&mut back).await?;
            assert_eq!(back, data);
            tracing::debug!("read done");
            Result::<(), Error>::Ok(())
        }
    )
    .map(|_| ())
}

fn launch_echo_server(
    parameters: ServerParameters,
) -> Result<(Arc<QuicServer>, impl Future<Output: Send>), Error> {
    let server = QuicServer::builder()
        .without_client_cert_verifier()
        .with_single_cert(
            include_bytes!("../../tests/keychain/localhost/server.cert"),
            include_bytes!("../../tests/keychain/localhost/server.key"),
        )
        .with_parameters(parameters)
        .with_qlog(qlogger())
        .listen("127.0.0.1:0".parse::<SocketAddr>()?)?;
    Ok((server.clone(), serve_echo(server)))
}

fn launch_test_client(parameters: ClientParameters) -> Arc<QuicClient> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(
        include_bytes!("../../tests/keychain/localhost/ca.cert").to_certificate(),
    );
    let client = QuicClient::builder()
        .with_root_certificates(roots)
        .with_parameters(parameters)
        .without_cert()
        .with_qlog(qlogger())
        .enable_sslkeylog()
        .build();

    Arc::new(client)
}

#[test]
fn single_stream() {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", server_addr)?;
        send_and_verify_echo(&connection, include_bytes!("tests.rs")).await?;

        Ok(())
    };
    run_serially(|| launch_echo_server(server_parameters()), launch_client).unwrap();
}

#[test]
fn empty_stream() -> Result<(), Error> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", server_addr)?;
        send_and_verify_echo(&connection, b"").await?;

        Ok(())
    };
    run_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn shutdown() -> Result<(), Error> {
    async fn serve_only_one_stream(server: Arc<QuicServer>) -> io::Result<()> {
        loop {
            let (connection, pathway) = server.accept().await?;
            tracing::info!(source = ?pathway.remote(), "accepted new connection");
            tokio::spawn(async move {
                let (_sid, (reader, writer)) = connection.accept_bi_stream().await?.unwrap();
                echo_stream(reader, writer).await?;
                connection.close("no error".into(), 0);
                Result::<(), Error>::Ok(())
            });
        }
    }

    let launch_server = || {
        let server = QuicServer::builder()
            .without_client_cert_verifier()
            .with_single_cert(
                include_bytes!("../../tests/keychain/localhost/server.cert"),
                include_bytes!("../../tests/keychain/localhost/server.key"),
            )
            .with_parameters(server_parameters())
            .with_qlog(qlogger())
            .listen("127.0.0.1:0".parse::<SocketAddr>()?)?;
        Ok((server.clone(), serve_only_one_stream(server)))
    };
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", server_addr)?;
        connection.handshaked().await; // 可有可无

        assert!(
            send_and_verify_echo(&connection, b"").await.is_err()
                || send_and_verify_echo(&connection, b"").await.is_err()
        );

        Result::Ok(())
    };
    run_serially(launch_server, launch_client)
}

const PARALLEL_ECHO_CONNS: usize = 2;
const PARALLEL_ECHO_STREAMS: usize = 10;

#[test]
fn parallel_stream() -> Result<(), Error> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());

        let mut streams = JoinSet::new();

        for conn_idx in 0..PARALLEL_ECHO_CONNS {
            let connection = client.connect("localhost", server_addr)?;
            for stream_idx in 0..PARALLEL_ECHO_STREAMS {
                let connection = connection.clone();
                streams.spawn(
                    async move { send_and_verify_echo(&connection, include_bytes!("tests.rs")).await }
                        .instrument(tracing::info_span!("stream", conn_idx, stream_idx)),
                );
            }
        }

        streams
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), Error>>()?;

        Ok(())
    };
    run_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn limited_streams() -> Result<(), Error> {
    fn client_parameters() -> ClientParameters {
        let mut params = ClientParameters::default();

        params.set_initial_max_streams_bidi(2u32);
        params.set_initial_max_streams_uni(0u32);
        params.set_initial_max_data(1u32 << 10);
        params.set_initial_max_stream_data_uni(1u32 << 10);
        params.set_initial_max_stream_data_bidi_local(1u32 << 10);
        params.set_initial_max_stream_data_bidi_remote(1u32 << 10);

        params
    }

    fn server_parameters() -> ServerParameters {
        let mut params = ServerParameters::default();

        params.set_initial_max_streams_bidi(2u32);
        params.set_initial_max_streams_uni(0u32);
        params.set_initial_max_data(1u32 << 10);
        params.set_initial_max_stream_data_uni(1u32 << 10);
        params.set_initial_max_stream_data_bidi_local(1u32 << 10);
        params.set_initial_max_stream_data_bidi_remote(1u32 << 10);

        params
    }

    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());

        let mut streams = JoinSet::new();

        for conn_idx in 0..PARALLEL_ECHO_CONNS / 2 {
            let connection = client.connect("localhost", server_addr)?;
            for stream_idx in 0..PARALLEL_ECHO_STREAMS / 2 {
                let connection = connection.clone();
                streams.spawn(
                    async move { send_and_verify_echo(&connection, include_bytes!("tests.rs")).await }
                        .instrument(tracing::info_span!("stream", conn_idx, stream_idx)),
                );
            }
        }

        streams
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), Error>>()?;

        Ok(())
    };
    run_serially(|| launch_echo_server(server_parameters()), launch_client)
}
