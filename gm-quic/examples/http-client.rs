use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use gm_quic::{QuicClient, ToCertificate, handy::client_parameters};
use http::{
    Uri,
    uri::{Authority, Parts},
};
use qevent::telemetry::handy::{DefaultSeqLogger, NullLogger};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader},
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Options {
    #[arg(long, help = "Save the qlog to a dir", value_name = "PATH")]
    qlog: Option<PathBuf>,
    #[arg(
        long,
        short,
        value_delimiter = ',',
        default_value = "tests/keychain/localhost/ca.cert",
        help = "Certificates of CA who issues the server certificate"
    )]
    roots: Vec<PathBuf>,
    #[arg(long, help = "Skip verification of server certificate")]
    skip_verify: bool,
    #[arg(long,action = clap::ArgAction::Set, help = "Reuse connection",default_value = "true")]
    reuse_connection: bool,
    #[arg(
        long,
        short,
        value_delimiter = ',',
        default_value = "[]",
        help = "ALPNs to use for the connection"
    )]
    alpns: Vec<Vec<u8>>,
    #[arg(long, help = "Save the response to a dir", value_name = "PATH")]
    save: Option<PathBuf>,
    #[arg(
        value_delimiter = ',',
        default_value = "http://localhost:4433/",
        help = "Uri to request. If only one uri is present and path is not specified, enter process mode"
    )]
    uris: Vec<Uri>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Err(error) = run(Options::parse()).await {
        tracing::info!(?error, "client error");
        std::process::exit(1);
    }
}

type Error = Box<dyn std::error::Error + Send + Sync>;

async fn run(options: Options) -> Result<(), Error> {
    if options.uris.is_empty() {
        return Err("no uri specified".into());
    }

    let qlogger: Arc<dyn qevent::telemetry::Log + Send + Sync> = match options.qlog {
        Some(dir) => Arc::new(DefaultSeqLogger::new(dir)),
        None => Arc::new(NullLogger),
    };

    let client_builder = if options.skip_verify {
        tracing::warn!("skip server verify");
        QuicClient::builder().without_verifier()
    } else {
        tracing::info!("load ca certs");
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        roots
            .add_parsable_certificates(options.roots.iter().flat_map(|path| path.to_certificate()));
        QuicClient::builder().with_root_certificates(roots)
    };

    let client_builder = if options.reuse_connection {
        client_builder.reuse_connection()
    } else {
        client_builder
    };

    let client = client_builder
        .with_qlog(qlogger)
        .without_cert()
        .with_parameters(client_parameters())
        .with_alpns(options.alpns)
        .enable_sslkeylog()
        .build();

    if options.uris.len() == 1 && options.uris[0].path() == "/" {
        return process(
            &client,
            &options.uris[0],
            options.save,
            options.reuse_connection,
        )
        .await;
    } else {
        for uri in options.uris {
            download(
                &client,
                uri,
                options.save.as_ref(),
                options.reuse_connection,
            )
            .await?;
        }
    }

    Ok(())
}

async fn process(
    client: &QuicClient,
    base_uri: &Uri,
    save: Option<PathBuf>,
    reuse: bool,
) -> Result<(), Error> {
    let mut stdin = BufReader::new(io::stdin());
    tracing::warn!(
        "enter interactive mode. Input content to request (e.g: Cargo.toml), input `exit` or `quic` to quit"
    );
    loop {
        let mut input = String::new();
        _ = stdin.read_line(&mut input).await?;

        let content = input.trim();
        if content.is_empty() {
            continue;
        }

        if content == "exit" || content == "quit" {
            return Ok(());
        }

        let mut uri_parts = Parts::default();
        uri_parts.scheme = base_uri.scheme().cloned();
        uri_parts.authority = base_uri.authority().cloned();
        uri_parts.path_and_query = Some(format!("/{content}").parse()?);
        download(client, Uri::from_parts(uri_parts)?, save.as_ref(), reuse).await?;
    }
}

async fn download(
    client: &QuicClient,
    uri: Uri,
    save: Option<&PathBuf>,
    reuse: bool,
) -> Result<(), Error> {
    let (server_name, server_addr) =
        lookup(uri.authority().ok_or("authority must be present in uri")?).await?;

    let file_path = uri.path().strip_prefix('/');
    let file_path = file_path.ok_or_else(|| format!("invalid path `{}`", uri.path()))?;

    let connection = client.connect(server_name, server_addr)?;
    let (_sid, (mut response, mut request)) = connection
        .open_bi_stream()
        .await?
        .expect("very very hard to exhaust the available stream ids");
    request
        .write_all(format!("GET /{file_path}").as_bytes())
        .await?;
    request.shutdown().await?;

    match save.map(|dir| dir.join(file_path)) {
        Some(path) => io::copy(&mut response, &mut fs::File::create(path).await?).await?,
        None => io::copy(&mut response, &mut io::stdout()).await?,
    };

    if !reuse {
        connection.close("done".into(), 0);
    }

    tracing::info!("saved to file {file_path}");
    Ok(())
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
