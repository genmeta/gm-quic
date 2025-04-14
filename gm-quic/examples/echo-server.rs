use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use gm_quic::{handy::*, *};
use qevent::telemetry::handy::{DefaultSeqLogger, NullLogger};
use tokio::io::{self, AsyncWriteExt};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "server")]
struct Options {
    #[arg(long, help = "Save the qlog to a dir", value_name = "PATH")]
    qlog: Option<PathBuf>,
    #[arg(
        short,
        long,
        value_delimiter = ',',
        default_values = ["127.0.0.1:4433", "[::1]:4433"],
        help = "What address:port to listen for new connections",
    )]
    listen: Vec<SocketAddr>,
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Err(error) = run(Options::parse()).await {
        tracing::info!(?error, "server error");
        std::process::exit(1);
    }
}

async fn run(options: Options) -> io::Result<()> {
    let qlogger: Arc<dyn qevent::telemetry::Log + Send + Sync> = match options.qlog {
        Some(dir) => Arc::new(DefaultSeqLogger::new(dir)),
        None => Arc::new(NullLogger),
    };

    let server = QuicServer::builder()
        .without_client_cert_verifier()
        .with_single_cert(options.certs.cert.as_path(), options.certs.key.as_path())
        .with_parameters(server_parameters())
        .with_qlog(qlogger)
        .listen(options.listen.as_slice())?;

    info!("listen on {:?}", server.addresses());

    serve_echo(server).await
}

async fn serve_echo(server: Arc<QuicServer>) -> io::Result<()> {
    async fn handle_stream(mut reader: StreamReader, mut writer: StreamWriter) -> io::Result<()> {
        io::copy(&mut reader, &mut writer).await?;
        writer.shutdown().await?;
        tracing::debug!("stream copy done");

        io::Result::Ok(())
    }

    loop {
        let (connection, pathway) = server.accept().await?;
        info!(source = ?pathway.remote(), "accepted new connection");
        tokio::spawn(async move {
            while let Ok(Some((_sid, (reader, writer)))) = connection.accept_bi_stream().await {
                tokio::spawn(handle_stream(reader, writer));
            }
        });
    }
}
