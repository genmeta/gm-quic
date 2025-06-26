use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use gm_quic::{handy::*, *};
use qevent::telemetry::handy::{DefaultSeqLogger, NoopLogger};
use tokio::io::{self, AsyncWriteExt};
use tracing::info;
use tracing_subscriber::prelude::*;

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
    #[arg(
        long,
        short,
        default_value = "128",
        help = "Maximum number of requests in the backlog. \
                If the backlog is full, new connections will be refused."
    )]
    backlog: usize,
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
    tracing_subscriber::registry()
        // .with(console_subscriber::spawn())
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(
                    tracing_subscriber::EnvFilter::builder()
                        .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
        .init();

    if let Err(error) = run(Options::parse()).await {
        tracing::info!(?error, "server error");
        std::process::exit(1);
    }
}

async fn run(options: Options) -> io::Result<()> {
    let qlogger: Arc<dyn qevent::telemetry::Log + Send + Sync> = match options.qlog {
        Some(dir) => Arc::new(DefaultSeqLogger::new(dir)),
        None => Arc::new(NoopLogger),
    };

    let listeners = QuicListeners::builder()?
        .without_client_cert_verifier()
        .with_parameters(server_parameters())
        .with_qlog(qlogger)
        .enable_0rtt()
        .listen(options.backlog)
        .await;
    listeners.add_server(
        options.certs.server_name.as_str(),
        options.certs.cert.as_path(),
        options.certs.key.as_path(),
        options.listen.as_slice(),
        None,
    )?;

    info!("listening on {:?}", listeners.servers());

    serve_echo(listeners).await
}

async fn serve_echo(listeners: Arc<QuicListeners>) -> io::Result<()> {
    async fn handle_stream(mut reader: StreamReader, mut writer: StreamWriter) -> io::Result<()> {
        io::copy(&mut reader, &mut writer).await?;
        writer.shutdown().await?;
        tracing::debug!("stream copy done");

        io::Result::Ok(())
    }

    loop {
        let (connection, _server, pathway, ..) = listeners.accept().await?;
        info!(source = ?pathway.remote(), "accepted new connection");
        tokio::spawn(async move {
            while let Ok((_sid, (reader, writer))) = connection.accept_bi_stream().await {
                tokio::spawn(handle_stream(reader, writer));
            }
        });
    }
}
