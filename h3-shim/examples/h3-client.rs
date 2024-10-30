use std::{net::IpAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use h3_shim::quic::rustls;
use rustls::pki_types::CertificateDer;
use tracing::error;

static ALPN: &[u8] = b"h3";

#[derive(Parser, Debug)]
#[structopt(name = "server")]
struct Opt {
    #[structopt(
        long,
        short,
        default_value = "examples/ca.cert",
        help = "Certificate of CA who issues the server certificate"
    )]
    pub ca: PathBuf,

    #[structopt(name = "keylog", long)]
    pub key_log_file: bool,

    #[structopt(long, short = 'b', default_value = "::")]
    pub bind: IpAddr,

    #[structopt(default_value = "https://localhost:4433/Cargo.toml")]
    pub uri: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()?;

    rt.block_on(run())
}

async fn run() -> Result<(), Box<dyn core::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stdout)
        .init();
    // console_subscriber::init();

    let opt = Opt::parse();

    // load CA certificates stored in the system
    let mut roots = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                if let Err(e) = roots.add(cert) {
                    error!("failed to parse trust anchor: {}", e);
                }
            }
        }
        Err(e) => {
            error!("couldn't load any default trust roots: {}", e);
        }
    };

    // load certificate of CA who issues the server certificate
    // NOTE that this should be used for dev only
    let ca = std::fs::read(opt.ca).expect("failed to read CA certificate");
    if let Err(e) = roots.add(CertificateDer::from(ca)) {
        error!("failed to parse trust anchor: {}", e);
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols.push(ALPN.into());

    let client = reqwest::Client::builder()
        .local_address(opt.bind)
        .use_preconfigured_tls(tls_config)
        .build()?;

    let response = client
        .get(&opt.uri)
        .version(http::Version::HTTP_3)
        .send()
        .await?;

    println!("response: {response:?}");
    println!("{}", response.text().await?);

    Ok(())
}
