use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use gm_quic::{QuicClient, ToCertificate, handy::client_parameters};
use http::uri::Authority;
use qlog::telemetry::handy::DefaultSeqLogger;
use rustls::RootCertStore;
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "server")]
struct Options {
    #[arg(
        long,
        short,
        value_delimiter = ',',
        default_value = "tests/keychain/localhost/ca.cert",
        help = "Certificates of CA who issues the server certificate"
    )]
    roots: Vec<PathBuf>,

    #[arg(default_value = "localhost:4433", help = "Host and port to connect to")]
    uri: Authority,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Err(error) = run(Options::parse()).await {
        tracing::info!(?error, "client error");
        std::process::exit(1);
    };
}

type Error = Box<dyn std::error::Error + Send + Sync>;

async fn run(options: Options) -> Result<(), Error> {
    let (server_name, server_addr) = lookup(&options.uri).await?;

    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    roots.add_parsable_certificates(options.roots.iter().flat_map(|path| path.to_certificate()));

    let client = QuicClient::builder()
        .with_root_certificates(roots)
        .without_cert()
        .with_parameters(client_parameters())
        .with_qlog(Arc::new(DefaultSeqLogger::new(PathBuf::from("/tmp/sqlog"))))
        .build();

    let connection = client.connect(server_name, server_addr)?;

    let mut stdin = io::BufReader::new(io::stdin());
    let mut stdout = io::stdout();

    loop {
        let (sid, (mut reader, mut writer)) = connection.open_bi_stream().await?.unwrap();
        info!(%sid, "opened bidi stream");

        stdout.write_all(b">").await?;
        stdout.flush().await?;

        let mut line = String::new();
        stdin.read_line(&mut line).await?;
        let line = line.trim();

        let mut echo = String::new();

        tokio::try_join!(
            async {
                tracing::debug!("client begin sending");
                writer.write_all(line.as_bytes()).await?;
                tracing::debug!("client sent: `{line}`");
                writer.shutdown().await?;
                tracing::debug!("client shutdown");
                Result::<_, Error>::Ok(())
            },
            async {
                reader.read_to_string(&mut echo).await?;
                info!("server echoed: `{echo}`");
                Result::<_, Error>::Ok(())
            }
        )?;
    }
}

async fn lookup(auth: &Authority) -> Result<(&str, SocketAddr), Error> {
    let mut addrs = tokio::net::lookup_host((auth.host(), auth.port_u16().unwrap_or(443)))
        .await?
        .collect::<Vec<_>>();
    addrs.sort_by_key(|a| a.is_ipv4());
    let addr = *addrs.first().ok_or("dns found no ipv6 addresses")?;
    tracing::info!("DNS lookup for {:?}: {:?}", auth.host(), addr);
    Ok((auth.host(), addr))
}
