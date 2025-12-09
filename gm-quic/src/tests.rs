use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use qbase::param::{ClientParameters, ServerParameters};
use qevent::telemetry::{Log, handy::*};
use rustls::{
    pki_types::{CertificateDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    runtime::Runtime,
    sync::Mutex,
    task::JoinSet,
    time,
};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;
use tracing_appender::non_blocking::WorkerGuard;

use crate::{
    prelude::{handy::*, *},
    qbase,
};

fn qlogger() -> Arc<dyn Log + Send + Sync> {
    static QLOGGER: OnceLock<Arc<dyn Log + Send + Sync>> = OnceLock::new();
    QLOGGER.get_or_init(|| Arc::new(NoopLogger)).clone()
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub fn test_serially<C, Sl, St>(
    launch_server: impl FnOnce() -> Sl,
    launch_client: impl FnOnce(SocketAddr) -> C,
) -> Result<(), BoxError>
where
    C: Future<Output = Result<(), BoxError>> + 'static,
    Sl: Future<Output = Result<(Arc<QuicListeners>, St), BoxError>> + Send + 'static,
    St: Future<Output: Send> + Send + 'static,
{
    static SUBSCRIBER: OnceLock<WorkerGuard> = OnceLock::new();

    SUBSCRIBER.get_or_init(|| {
        let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
        tracing_subscriber::fmt()
            .with_writer(non_blocking)
            .with_max_level(tracing::Level::DEBUG)
            .with_file(true)
            .with_line_number(true)
            .init();
        guard
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
        let _server_task = AbortOnDropHandle::new(tokio::spawn(server_task));
        let localhost = listeners
            .get_server("localhost")
            .expect("Server localhost must be registered");
        let localhost_bind_interface = localhost
            .bind_interfaces()
            .into_iter()
            .next()
            .map(|(_bind_uri, interface)| interface)
            .expect("Server should bind at least one address");
        let server_addr = localhost_bind_interface
            .borrow()?
            .real_addr()?
            .try_into()
            .expect("This test support only SocketAddr");

        let result = time::timeout(Duration::from_secs(30), launch_client(server_addr)).await;

        listeners.shutdown();
        _server_task.abort();

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

async fn echo_stream(mut reader: StreamReader, mut writer: StreamWriter) {
    io::copy(&mut reader, &mut writer).await.unwrap();
    writer.shutdown().await.unwrap();
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
    parameters: ServerParameters,
) -> Result<(Arc<QuicListeners>, impl Future<Output: Send>), BoxError> {
    let listeners = QuicListeners::builder()?
        .without_client_cert_verifier()
        .with_parameters(parameters)
        .with_qlog(qlogger())
        .listen(128);
    listeners.add_server(
        "localhost",
        SERVER_CERT,
        SERVER_KEY,
        [BindUri::from("inet://127.0.0.1:0?alloc_port=true").alloc_port()],
        None,
    )?;
    Ok((listeners.clone(), serve_echo(listeners)))
}

fn launch_test_client(parameters: ClientParameters) -> Arc<QuicClient> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap));
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
fn single_stream() -> Result<(), BoxError> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", [server_addr])?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn signal_big_stream() -> Result<(), BoxError> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", [server_addr])?;
        send_and_verify_echo(&connection, &TEST_DATA.to_vec().repeat(1024)).await?;

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn empty_stream() -> Result<(), BoxError> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", [server_addr])?;
        send_and_verify_echo(&connection, b"").await?;

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn shutdown() -> Result<(), BoxError> {
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

    let launch_server = || async {
        let listeners = QuicListeners::builder()?
            .without_client_cert_verifier()
            .with_parameters(server_parameters())
            .with_qlog(qlogger())
            .listen(128);
        listeners.add_server(
            "localhost",
            SERVER_CERT,
            SERVER_KEY,
            [BindUri::from("inet://127.0.0.1:0?alloc_port=true").alloc_port()],
            None,
        )?;
        Ok((listeners.clone(), serve_only_one_stream(listeners)))
    };
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", [server_addr])?;
        _ = connection.handshaked().await; // 可有可无

        assert!(
            send_and_verify_echo(&connection, b"").await.is_err()
                || send_and_verify_echo(&connection, b"").await.is_err()
        );

        connection.terminated().await;

        Result::Ok(())
    };
    test_serially(launch_server, launch_client)
}

#[test]
fn idle_timeout() {
    fn server_parameters() -> ServerParameters {
        let mut params = handy::server_parameters();
        params
            .set(ParameterId::MaxIdleTimeout, Duration::from_secs(1))
            .expect("unreachable");

        params
    }

    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", [server_addr])?;
        connection.terminated().await;
        Result::Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client).unwrap();
}

#[test]
fn double_connections() -> Result<(), BoxError> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());

        let mut connections = JoinSet::new();

        for conn_idx in 0..2 {
            let connection = client.connect("localhost", [server_addr])?;
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

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

const PARALLEL_ECHO_CONNS: usize = 20;
const PARALLEL_ECHO_STREAMS: usize = 2;

#[test]
fn parallel_stream() -> Result<(), BoxError> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());

        let mut streams = JoinSet::new();

        for conn_idx in 0..PARALLEL_ECHO_CONNS {
            let connection = client.connect("localhost", [server_addr])?;
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

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn parallel_big_stream() -> Result<(), BoxError> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());

        let mut big_streams = JoinSet::new();
        let test_data = Arc::new(TEST_DATA.to_vec().repeat(32));

        for conn_idx in 0..PARALLEL_ECHO_CONNS {
            let connection = client.connect("localhost", [server_addr])?;
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

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn limited_streams() -> Result<(), BoxError> {
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

    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());

        let mut streams = JoinSet::new();

        for conn_idx in 0..PARALLEL_ECHO_CONNS / 2 {
            let connection = client.connect("localhost", [server_addr])?;
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

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn client_without_verify() -> Result<(), BoxError> {
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
        let connection = client.connect("localhost", [server_addr])?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        Ok(())
    };
    test_serially(|| launch_echo_server(server_parameters()), launch_client)
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
    server_parameters: ServerParameters,
) -> Result<(Arc<QuicListeners>, impl Future<Output: Send>), BoxError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap));
    let listeners = QuicListeners::builder()?
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
        )
        .with_client_auther(ClientNameAuther::<SILENT_REFUSE>)
        .with_parameters(server_parameters)
        .with_qlog(qlogger())
        .listen(128);
    listeners.add_server(
        "localhost",
        SERVER_CERT,
        SERVER_KEY,
        [BindUri::from("inet://127.0.0.1:0?alloc_port=true").alloc_port()],
        None,
    )?;
    Ok((listeners.clone(), serve_echo(listeners)))
}

#[test]
fn auth_client_name() -> Result<(), BoxError> {
    const SILENT_REFUSE: bool = false;
    let launch_client = |server_addr| async move {
        let client = {
            let mut parameters = client_parameters();
            _ = parameters.set(ParameterId::ClientName, "client".to_string());

            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client.connect("localhost", [server_addr])?;
        send_and_verify_echo(&connection, TEST_DATA).await?;

        Ok(())
    };
    test_serially(
        || launch_client_auth_test_server::<SILENT_REFUSE>(server_parameters()),
        launch_client,
    )
}

#[test]
fn auth_client_name_incorrect_name() -> Result<(), BoxError> {
    const SILENT_REFUSE: bool = false;
    let launch_client = |server_addr| async move {
        let client = {
            let mut parameters = client_parameters();
            _ = parameters.set(ParameterId::ClientName, "another_client".to_string());

            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client.connect("localhost", [server_addr])?;
        let error = connection.terminated().await;
        assert_eq!(error.kind(), ErrorKind::ConnectionRefused);

        Ok(())
    };
    test_serially(
        || launch_client_auth_test_server::<SILENT_REFUSE>(server_parameters()),
        launch_client,
    )
}
#[test]
fn auth_client_refuse() -> Result<(), BoxError> {
    const SILENT_REFUSE: bool = false;
    let launch_client = |server_addr| async move {
        let client = {
            let parameters = client_parameters();
            // no CLIENT_NAME

            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client.connect("localhost", [server_addr])?;

        let error = connection.terminated().await;
        assert_eq!(error.kind(), ErrorKind::ConnectionRefused);

        Ok(())
    };
    test_serially(
        || launch_client_auth_test_server::<SILENT_REFUSE>(server_parameters()),
        launch_client,
    )
}

#[test]
fn auth_client_refuse_silently() -> Result<(), BoxError> {
    const SILENT_REFUSE: bool = true;
    let launch_client = |server_addr| async move {
        let client = {
            let parameters = client_parameters();
            // no CLIENT_NAME

            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client.connect("localhost", [server_addr])?;

        assert!(
            time::timeout(Duration::from_secs(3), connection.handshaked())
                .await
                .is_err()
        );

        Ok(())
    };
    test_serially(
        || launch_client_auth_test_server::<SILENT_REFUSE>(server_parameters()),
        launch_client,
    )
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
    parameters: ServerParameters,
) -> Result<(Arc<QuicListeners>, impl Future<Output: Send>), BoxError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap));
    let listeners = QuicListeners::builder()?
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
        )
        .with_parameters(parameters)
        .with_qlog(qlogger())
        .listen(128);
    listeners.add_server(
        "localhost",
        SERVER_CERT,
        SERVER_KEY,
        [BindUri::from("inet://127.0.0.1:0?alloc_port=true").alloc_port()],
        None,
    )?;
    Ok((listeners.clone(), serve_echo_with_sign_verify(listeners)))
}

#[test]
fn sign_and_verify() -> Result<(), BoxError> {
    let launch_client = |server_addr| async move {
        let client = {
            let mut parameters = client_parameters();
            _ = parameters.set(ParameterId::ClientName, "client".to_string());

            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap),
            );
            let client = QuicClient::builder()
                .with_root_certificates(roots)
                .with_parameters(parameters)
                .with_cert(CLIENT_CERT, CLIENT_KEY)
                .with_qlog(qlogger())
                .enable_sslkeylog()
                .build();

            Arc::new(client)
        };
        let connection = client.connect("localhost", [server_addr])?;
        send_and_verify_echo_with_sign_verify(&connection, TEST_DATA).await?;

        Ok(())
    };
    test_serially(
        || launch_echo_with_sign_verify_server(server_parameters()),
        launch_client,
    )
}
