use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use gm_quic::{Connection, QuicListeners, StreamReader, StreamWriter, handy::server_parameters};
use qevent::telemetry::handy::{DefaultSeqLogger, NoopLogger};
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncWriteExt},
};

#[derive(Parser, Debug)]
#[command(name = "server")]
struct Options {
    #[arg(
        name = "dir",
        short,
        long,
        help = "Root directory of the files to serve. \
                If omitted, server will respond OK.",
        default_value = "./"
    )]
    root: PathBuf,
    #[arg(long, help = "Save the qlog to a dir", value_name = "PATH")]
    qlog: Option<PathBuf>,
    #[arg(
        short,
        long,
        value_delimiter = ',',
        default_values = ["127.0.0.1:4433", "[::1]:4433"],
        help = "What address:port to listen for new connections"
    )]
    listen: Vec<SocketAddr>,
    #[arg(
        long,
        short,
        value_delimiter = ',',
        default_value = "quic",
        help = "ALPNs to use for the connection"
    )]
    alpns: Vec<Vec<u8>>,
    #[command(flatten)]
    certs: Certs,
}

#[derive(Parser, Debug)]
struct Certs {
    #[arg(long, short, default_value = "localhost", help = "Server name.")]
    server_name: String,
    #[arg(
        long,
        short,
        default_value = "tests/keychain/localhost/server.cert",
        help = "Certificate for TLS. If present, `--key` is mandatory."
    )]
    cert: PathBuf,
    #[arg(
        long,
        short,
        default_value = "tests/keychain/localhost/server.key",
        help = "Private key for the certificate."
    )]
    key: PathBuf,
}

type Error = Box<dyn std::error::Error + Send + Sync>;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        // default value 512 out of macos ulimit
        .max_blocking_threads(256)
        .build()
        .expect("failed to build tokio runtime");

    if let Err(error) = rt.block_on(run(Options::parse())) {
        tracing::info!(?error, "server error");
        std::process::exit(1);
    }
}

async fn run(options: Options) -> Result<(), Error> {
    let qlogger: Arc<dyn qevent::telemetry::Log + Send + Sync> = match options.qlog {
        Some(dir) => Arc::new(DefaultSeqLogger::new(dir)),
        None => Arc::new(NoopLogger),
    };

    let listeners = QuicListeners::builder()?
        .with_qlog(qlogger)
        .without_client_cert_verifier()
        .with_parameters(server_parameters())
        .with_alpns(options.alpns)
        .listen(128)
        .await;
    listeners.add_server(
        options.certs.server_name.as_str(),
        options.certs.cert.as_path(),
        options.certs.key.as_path(),
        options.listen.as_slice(),
        None,
    )?;
    tracing::info!("listen  {:?}", listeners.servers());

    loop {
        let (connection, _server, _pathway, _link) = listeners.accept().await?;
        tokio::spawn(serve_files(connection));
    }
}

async fn serve_files(connection: Arc<Connection>) -> Result<(), Error> {
    async fn serve_file(mut reader: StreamReader, mut writer: StreamWriter) -> Result<(), Error> {
        let mut request = String::new();
        reader.read_to_string(&mut request).await?;
        tracing::info!("Received request: {request}");

        // HTTP/0.9 is very simple - just a GET request with a path
        let serve = async {
            match request.trim().strip_prefix("GET /") {
                Some(path) => {
                    tracing::debug!(?path, "Received HTTP/0.9 request");
                    let mut file = fs::File::open(PathBuf::from_iter(["./", path])).await?;
                    io::copy(&mut file, &mut writer).await.map(|_| ())
                }
                None => Err(io::Error::other(format!(
                    "Invalid HTTP/0.9 request: {request}",
                ))),
            }
        };

        if let Err(error) = serve.await {
            tracing::warn!("failed to serve request: {}", error);
        }

        _ = writer.shutdown().await;

        Ok(())
    }

    loop {
        let (_sid, (reader, writer)) = connection.accept_bi_stream().await?.expect("unreachable");
        tokio::spawn(serve_file(reader, writer));
    }
}
