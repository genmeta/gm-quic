mod echo;
mod lost;

use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock, Once},
    time::Duration,
};

use qevent::telemetry::{Log, handy::*};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    runtime::Runtime,
    task::JoinSet,
    time,
};
use tracing::Instrument;

use crate::{handy::*, *};

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

    static RT: LazyLock<Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create runtime")
    });

    RT.block_on(async move {
        static LOCK: LazyLock<Arc<tokio::sync::Mutex<()>>> = LazyLock::new(Default::default);
        let _lock = LOCK.lock().await;

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

const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

const PARALLEL_ECHO_CONNS: usize = 2;
const PARALLEL_ECHO_STREAMS: usize = 10;

// static QLOGGER: LazyLock<Arc<dyn Log + Send + Sync>> = LazyLock::new(|| Arc::new(NullLogger));
static QLOGGER: LazyLock<Arc<dyn Log + Send + Sync>> = LazyLock::new(|| Arc::new(NullLogger));

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

fn launch_test_client(parameters: ClientParameters) -> Arc<QuicClient> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CA_CERT.to_certificate());
    let client = QuicClient::builder()
        .with_root_certificates(roots)
        .with_parameters(parameters)
        .without_cert()
        .with_qlog(QLOGGER.clone())
        .enable_sslkeylog()
        .build();

    Arc::new(client)
}
