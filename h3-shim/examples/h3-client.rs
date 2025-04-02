use std::path::PathBuf;

use clap::Parser;
use futures::future;
use gm_quic::ToCertificate;
use tokio::io::AsyncWriteExt;

static ALPN: &[u8] = b"h3";

#[derive(Parser, Debug)]
#[structopt(name = "server")]
pub struct Options {
    #[structopt(
        long,
        short,
        default_value = "h3-shim/examples/ca.cert",
        help = "Certificate of CA who issues the server certificate"
    )]
    pub ca: PathBuf,

    #[structopt(
        default_value = "https://localhost:4433/Cargo.lock",
        help = "URI to request"
    )]
    pub uri: String,
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[cfg_attr(test, allow(unused))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stdout)
        .init();
    // console_subscriber::init();

    run(Options::parse()).await
}

pub async fn run(options: Options) -> Result<()> {
    // DNS lookup

    let uri = options.uri.parse::<http::Uri>()?;
    if uri.scheme() != Some(&http::uri::Scheme::HTTPS) {
        return Err("uri scheme must be 'https'")?;
    }

    let auth = uri.authority().ok_or("uri must have a host")?.clone();
    let addr = tokio::net::lookup_host((auth.host(), auth.port_u16().unwrap_or(443)))
        .await?
        .next()
        .ok_or("dns found no addresses")?;
    tracing::info!("DNS lookup for {:?}: {:?}", auth.host(), addr);

    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(options.ca.to_certificate());

    let quic_client = ::gm_quic::QuicClient::builder()
        .with_root_certificates(roots)
        .without_cert()
        .with_alpns([ALPN])
        .with_parameters(client_parameters())
        .build();
    tracing::info!(%addr, "connect to server");
    let conn = quic_client.connect(auth.host(), addr)?;

    let gm_quic_conn = h3_shim::QuicConnection::new(conn).await;
    let (mut conn, mut h3_client) = h3::client::new(gm_quic_conn).await?;
    let driver = async move {
        future::poll_fn(|cx| conn.poll_close(cx)).await?;
        Result::Ok(())
    };

    let request = async move {
        tracing::info!(%uri, "request");

        let request = http::Request::builder().uri(uri).body(())?;

        // sending request results in a bidirectional stream,
        // which is also used for receiving response
        let mut stream = h3_client.send_request(request).await?;
        // shutdown on the sending side, no more data for the GET request
        stream.finish().await?;

        let response = stream.recv_response().await?;
        tracing::info!(?response, "received");

        // `recv_data()` must be called after `recv_response()` for
        // receiving potential response body
        while let Some(mut chunk) = stream.recv_data().await? {
            tokio::io::stdout().write_all_buf(&mut chunk).await?;
        }

        Result::Ok(())
    };

    tokio::try_join!(driver, request,)?;

    Ok(())
}

fn client_parameters() -> gm_quic::ClientParameters {
    let mut params = gm_quic::ClientParameters::default();

    params.set_initial_max_streams_bidi(100u32);
    params.set_initial_max_streams_uni(100u32);
    params.set_initial_max_data(1u32 << 20);
    params.set_initial_max_stream_data_uni(1u32 << 20);
    params.set_initial_max_stream_data_bidi_local(1u32 << 20);
    params.set_initial_max_stream_data_bidi_remote(1u32 << 20);

    params
}
