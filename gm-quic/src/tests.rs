use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, Once},
    time::Duration,
};

use qevent::telemetry::{Log, handy::*};
use qinterface::ifaces::QuicInterfaces;
use rustls::server::WebPkiClientVerifier;
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
    QLOGGER.get_or_init(|| Arc::new(NoopLogger)).clone()
}

pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub fn test_serially<C, Sl, St>(
    launch_server: impl FnOnce() -> Sl,
    launch_client: impl FnOnce(SocketAddr) -> C,
) -> Result<(), Error>
where
    C: Future<Output = Result<(), Error>> + 'static,
    Sl: Future<Output = Result<(Arc<QuicListeners>, St), Error>> + Send + 'static,
    St: Future<Output: Send> + Send + 'static,
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

        let (listeners, server_task) = launch_server().await?;
        let server_task = tokio::task::spawn(server_task);
        let server_addr = QuicInterfaces::global()
            .get(
                listeners.servers()["localhost"]
                    .iter()
                    .next()
                    .expect("Server should bind at least one address"),
            )
            .expect("Server should bind the address successfully")
            .real_addr()?
            .try_into()
            .expect("This test support only SocketAddr");

        let result = time::timeout(Duration::from_secs(10), launch_client(server_addr)).await;

        listeners.shutdown().await;
        server_task.abort();

        result?.expect("test timeout");
        Ok(())
    })
}

const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");
const CLIENT_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/client.cert");
const CLIENT_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/client.key");
const TEST_DATA: &[u8] = include_bytes!("tests.rs");

async fn echo_stream(mut reader: StreamReader, mut writer: StreamWriter) -> io::Result<()> {
    io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    tracing::debug!("stream copy done");

    io::Result::Ok(())
}

pub async fn serve_echo(listeners: Arc<QuicListeners>) -> io::Result<()> {
    loop {
        let (connection, server, pathway, _link) = listeners.accept().await?;
        assert_eq!(server, "localhost");
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

async fn launch_echo_server(
    parameters: ServerParameters,
) -> Result<(Arc<QuicListeners>, impl Future<Output: Send>), Error> {
    let listeners = QuicListeners::builder()?
        .without_client_cert_verifier()
        .with_parameters(parameters)
        .with_qlog(qlogger())
        .listen(128)
        .await;
    listeners.add_server(
        "localhost",
        SERVER_CERT,
        SERVER_KEY,
        ["inet://127.0.0.1/alloc"],
        None,
    )?;
    Ok((listeners.clone(), serve_echo(listeners)))
}

fn launch_test_client(parameters: ClientParameters) -> Arc<QuicClient> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CA_CERT.to_certificate());
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
fn single_stream() -> Result<(), Error> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", server_addr)?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn signal_big_stream() -> Result<(), Error> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", server_addr)?;
        send_and_verify_echo(&connection, &TEST_DATA.to_vec().repeat(1024)).await?;

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn empty_stream() -> Result<(), Error> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", server_addr)?;
        send_and_verify_echo(&connection, b"").await?;

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn shutdown() -> Result<(), Error> {
    async fn serve_only_one_stream(listeners: Arc<QuicListeners>) -> io::Result<()> {
        loop {
            let (connection, _server, pathway, _link) = listeners.accept().await?;
            tracing::info!(source = ?pathway.remote(), "accepted new connection");
            tokio::spawn(async move {
                let (_sid, (reader, writer)) = connection.accept_bi_stream().await?.unwrap();
                echo_stream(reader, writer).await?;
                connection.close("Bye bye", 0);
                Result::<(), Error>::Ok(())
            });
        }
    }

    let launch_server = || async {
        let listeners = QuicListeners::builder()?
            .without_client_cert_verifier()
            .with_parameters(server_parameters())
            .with_qlog(qlogger())
            .listen(128)
            .await;
        listeners.add_server(
            "localhost",
            SERVER_CERT,
            SERVER_KEY,
            ["inet://127.0.0.1/alloc"],
            None,
        )?;
        Ok((listeners.clone(), serve_only_one_stream(listeners)))
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
    test_serially(launch_server, launch_client)
}

#[test]
fn idle_timeout() {
    fn server_parameters() -> ServerParameters {
        let mut params = ServerParameters::default();

        params.set_initial_max_streams_bidi(2u32);
        params.set_initial_max_streams_uni(0u32);
        params.set_initial_max_data(1u32 << 10);
        params.set_initial_max_stream_data_uni(1u32 << 10);
        params.set_initial_max_stream_data_bidi_local(1u32 << 10);
        params.set_initial_max_stream_data_bidi_remote(1u32 << 10);
        params.set_max_idle_timeout(Duration::from_secs(1)); // from 10s to 1s

        params
    }

    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", server_addr)?;
        connection.terminated().await;
        Result::Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client).unwrap();
}

#[test]
fn double_connections() -> Result<(), Error> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());

        let mut connections = JoinSet::new();

        for conn_idx in 0..2 {
            let connection = client.connect("localhost", server_addr)?;
            connections.spawn(
                async move { send_and_verify_echo(&connection, TEST_DATA).await }
                    .instrument(tracing::info_span!("stream", conn_idx)),
            );
        }

        connections
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), Error>>()?;

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

const PARALLEL_ECHO_CONNS: usize = 20;
const PARALLEL_ECHO_STREAMS: usize = 2;

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
                    async move { send_and_verify_echo(&connection, TEST_DATA).await }
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
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn parallel_big_stream() -> Result<(), Error> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());

        let mut big_streams = JoinSet::new();
        // about 10MB
        let test_data = Arc::new(TEST_DATA.to_vec().repeat(128));

        for conn_idx in 0..PARALLEL_ECHO_CONNS {
            let connection = client.connect("localhost", server_addr)?;
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
            .collect::<Result<(), Error>>()?;

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
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
        params.set_max_idle_timeout(Duration::from_secs(10));

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
                    async move { send_and_verify_echo(&connection, TEST_DATA).await }
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
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn client_without_verify() -> Result<(), Error> {
    let launch_client = |server_addr| async move {
        let client = {
            let parameters = client_parameters();
            let client = QuicClient::builder()
                .without_verifier()
                .with_parameters(parameters)
                .without_cert()
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();
            Arc::new(client)
        };
        let connection = client.connect("localhost", server_addr)?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn client_auth() -> Result<(), Error> {
    pub async fn auth_client(listeners: Arc<QuicListeners>) -> io::Result<()> {
        loop {
            let (connection, server, _pathway, _link) = listeners.accept().await?;
            assert_eq!(server, "localhost");

            match connection.peer_certs().await?.as_ref() {
                PeerCert::CertOrPublicKey(cert) => {
                    let cert = rcgen::CertificateParams::from_ca_cert_der(&cert.as_slice().into())
                        .unwrap();
                    let client = rcgen::Ia5String::try_from("client").unwrap();
                    assert!(
                        (cert.distinguished_name.get(&rcgen::DnType::CommonName)).is_some_and(
                            |cn| matches!(cn, rcgen::DnValue::Ia5String(cn) if  cn == &client),
                        ) || cert.subject_alt_names.iter().any(
                            |name| matches!(name, rcgen::SanType::DnsName(name) if name == &client),
                        )
                    );
                }
                PeerCert::None => {
                    panic!("Client should present a certificate")
                }
            }

            tokio::spawn(async move {
                while let Ok(Some((_sid, (reader, writer)))) = connection.accept_bi_stream().await {
                    tokio::spawn(echo_stream(reader, writer));
                }
            });
        }
    }
    let launch_server = || async {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(CA_CERT.to_certificate());
        let listeners = QuicListeners::builder()?
            .with_client_cert_verifier(
                WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .unwrap(),
            )
            .with_parameters(server_parameters())
            .with_qlog(qlogger())
            .listen(128)
            .await;
        listeners.add_server(
            "localhost",
            SERVER_CERT,
            SERVER_KEY,
            ["inet://127.0.0.1/alloc"],
            None,
        )?;
        Ok((listeners.clone(), auth_client(listeners)))
    };
    test_serially(launch_server, |server_addr| async move {
        let client = {
            let parameters = client_parameters();
            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(CA_CERT.to_certificate());
            let client = QuicClient::builder()
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client.connect("localhost", server_addr)?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        Ok(())
    })
}
