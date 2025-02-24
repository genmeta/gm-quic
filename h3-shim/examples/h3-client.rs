use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use futures::future;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use tokio::io::AsyncWriteExt;
use tracing::{Instrument, error, info, info_span, trace};

static ALPN: &[u8] = b"h3";

#[derive(Parser, Debug)]
#[structopt(name = "server")]
pub struct Opt {
    #[structopt(
        long,
        short,
        default_value = "h3-shim/examples/ca.cert",
        help = "Certificate of CA who issues the server certificate"
    )]
    pub ca: PathBuf,

    #[structopt(name = "keylog", long)]
    pub key_log_file: bool,

    #[structopt(long, short = 'b', default_value = "[::]:0")]
    pub bind: Vec<SocketAddr>,

    #[structopt(default_value = "https://localhost:4433/Cargo.lock")]
    pub uri: String,
}

#[cfg_attr(test, allow(unused))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn core::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stdout)
        .init();
    // console_subscriber::init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let opt = Opt::parse();

    run(opt).await
}

pub async fn run(opt: Opt) -> Result<(), Box<dyn core::error::Error + Send + Sync>> {
    // DNS lookup

    let uri = opt.uri.parse::<http::Uri>()?;
    if uri.scheme() != Some(&http::uri::Scheme::HTTPS) {
        return Err("uri scheme must be 'https'")?;
    }

    let auth = uri.authority().ok_or("uri must have a host")?.clone();
    let port = auth.port_u16().unwrap_or(443);
    let addr = tokio::net::lookup_host((auth.host(), port))
        .await?
        .next()
        .ok_or("dns found no addresses")?;
    info!("DNS lookup for {:?}: {:?}", uri, addr);

    // create quinn client endpoint

    // load CA certificates stored in the system
    let mut roots = rustls::RootCertStore::empty();
    let cert_result = rustls_native_certs::load_native_certs();
    for err in cert_result.errors {
        error!("failed to load trust anchor: {}", err);
    }
    for cert in cert_result.certs {
        if let Err(e) = roots.add(cert) {
            error!("failed to parse trust anchor: {}", e);
        }
    }
    // load certificate of CA who issues the server certificate
    // NOTE that this should be used for dev only
    if let Err(e) = roots.add(CertificateDer::from_pem_file(opt.ca).unwrap()) {
        panic!("failed to parse trust anchor: {}", e);
    }

    let mut params = h3_shim::ClientParameters::default();
    params.set_initial_max_streams_bidi(100);
    params.set_initial_max_streams_uni(100);
    params.set_initial_max_data((1u32 << 20).into());
    params.set_initial_max_stream_data_uni((1u32 << 20).into());
    params.set_initial_max_stream_data_bidi_local((1u32 << 20).into());
    params.set_initial_max_stream_data_bidi_remote((1u32 << 20).into());

    trace!(bind = ?opt.bind, "build QuicClient");
    let quic_client = ::gm_quic::QuicClient::builder()
        .with_root_certificates(roots)
        .without_cert()
        .with_keylog(opt.key_log_file)
        .with_alpns([ALPN.into()])
        .with_parameters(params)
        .bind(&opt.bind[..])?
        .build();
    info!(%addr, "connecting to server");
    let conn = quic_client.connect(auth.host(), addr)?;

    // create h3 client

    let gm_quic_conn = h3_shim::QuicConnection::new(conn).await;
    let (mut conn, mut send_request) = h3::client::new(gm_quic_conn).await?;
    info!("handshake done");
    let driver = async move {
        future::poll_fn(|cx| conn.poll_close(cx)).await?;
        // tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok::<_, Box<dyn std::error::Error + 'static + Send + Sync>>(())
    };

    // In the following block, we want to take ownership of `send_request`:
    // the connection will be closed only when all `SendRequest`s instances
    // are dropped.
    //
    //             So we "move" it.
    //                  vvvv
    let request = async move {
        info!(%uri,"sending request ...");

        let req = http::Request::builder().uri(uri).body(())?;

        // sending request results in a bidirectional stream,
        // which is also used for receiving response
        let mut stream = send_request.send_request(req).await?;

        // finish on the sending side
        info!("waiting for peer to receive the request");
        stream.finish().await?;

        info!("receiving response ...");
        let resp = stream.recv_response().await?;
        info!("response: {:?} {}", resp.version(), resp.status());
        info!("headers: {:#?}", resp.headers());

        // `recv_data()` must be called after `recv_response()` for
        // receiving potential response body
        let mut out = tokio::io::stdout();
        while let Some(mut chunk) = stream.recv_data().await? {
            out.write_all_buf(&mut chunk).await?;
            out.flush().await?;
        }

        info!("all data received");

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok::<_, Box<dyn std::error::Error + 'static + Send + Sync>>(())
    }
    .instrument(info_span!("request"));

    let derive = tokio::spawn(driver);
    let request = tokio::spawn(request);

    derive.await??;
    request.await??;

    Ok(())
}
