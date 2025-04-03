use std::{net::SocketAddr, ops::Deref, path::PathBuf, sync::Arc, time::Duration};

use bytes::{Bytes, BytesMut};
use clap::Parser;
use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use http::{Request, StatusCode};
use tokio::{fs::File, io::AsyncReadExt};
use tracing::{error, info};

#[derive(Parser, Debug)]
#[structopt(name = "server")]
pub struct Options {
    #[structopt(
        name = "dir",
        short,
        long,
        help = "Root directory of the files to serve. \
                If omitted, server will respond OK.",
        default_value = "./"
    )]
    pub root: PathBuf,
    #[structopt(
        short,
        long,
        default_values = ["127.0.0.1:4433", "[::1]:4433"],
        help = "What address:port to listen for new connections"
    )]
    pub listen: Vec<SocketAddr>,
    #[structopt(flatten)]
    pub certs: Certs,
}

#[derive(Parser, Debug)]
pub struct Certs {
    #[structopt(long, short, default_value = "localhost", help = "Server name.")]
    pub server_name: String,
    #[structopt(
        long,
        short,
        default_value = "h3-shim/examples/server.cert",
        help = "Certificate for TLS. If present, `--key` is mandatory."
    )]
    pub cert: PathBuf,
    #[structopt(
        long,
        short,
        default_value = "h3-shim/examples/server.key",
        help = "Private key for the certificate."
    )]
    pub key: PathBuf,
}

static ALPN: &[u8] = b"h3";

#[cfg_attr(test, allow(unused))]
#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(true)
        .init();
    // console_subscriber::init();

    run(Options::parse()).await
}

pub async fn run(options: Options) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("serving {}", options.root.display());
    let root = Arc::new(options.root);
    if !root.is_dir() {
        return Err(format!("{}: is not a readable directory", root.display()).into());
    }
    let Certs {
        server_name,
        cert,
        key,
    } = options.certs;

    let quic_server = ::gm_quic::QuicServer::builder()
        .with_supported_versions([1u32])
        .without_client_cert_verifier()
        .with_parameters(server_parameters())
        .enable_sni()
        .add_host(server_name, cert.as_path(), key.as_path())
        .with_alpns([ALPN.to_vec()])
        .listen(&options.listen[..])?;
    info!("listen on {:?}", quic_server.addresses());

    // handle incoming connections and requests
    while let Ok((new_conn, _pathway)) = quic_server.accept().await {
        let h3_conn =
            match h3::server::Connection::new(h3_shim::QuicConnection::new(new_conn).await).await {
                Ok(h3_conn) => {
                    info!("accept a new quic connection");
                    h3_conn
                }
                Err(error) => {
                    tracing::error!("failed to establish h3 connection: {}", error);
                    continue;
                }
            };
        let root = root.clone();
        tokio::spawn(handle_connection(root, h3_conn));
    }

    Ok(())
}

fn server_parameters() -> gm_quic::ServerParameters {
    let mut params = gm_quic::ServerParameters::default();

    params.set_initial_max_streams_bidi(100u32);
    params.set_initial_max_streams_uni(100u32);
    params.set_initial_max_data(1u32 << 20);
    params.set_initial_max_stream_data_uni(1u32 << 20);
    params.set_initial_max_stream_data_bidi_local(1u32 << 20);
    params.set_initial_max_stream_data_bidi_remote(1u32 << 20);
    params.set_max_idle_timeout(Duration::from_secs(30));

    params
}

async fn handle_connection<T>(
    serve_root: Arc<PathBuf>,
    mut connection: h3::server::Connection<T, Bytes>,
) where
    T: h3::quic::Connection<Bytes>,
    <T as h3::quic::OpenStreams<Bytes>>::BidiStream: h3::quic::BidiStream<Bytes> + Send + 'static,
{
    loop {
        match connection.accept().await {
            Ok(Some((request, stream))) => {
                info!(?request, "handle");
                let serve_root = serve_root.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(request, stream, serve_root).await {
                        error!("handling request failed: {}", e);
                    }
                });
            }
            Ok(None) => break,
            Err(error) => match error.get_error_level() {
                ErrorLevel::ConnectionError => break,
                ErrorLevel::StreamError => continue,
            },
        }
    }
}

#[tracing::instrument(skip_all)]
async fn handle_request<T>(
    request: Request<()>,
    mut stream: RequestStream<T, Bytes>,
    serve_root: Arc<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    let (status, to_serve) = match serve_root.deref() {
        _ if request.uri().path().contains("..") => (StatusCode::NOT_FOUND, None),
        root => {
            let to_serve = root.join(request.uri().path().strip_prefix('/').unwrap_or(""));
            match File::open(&to_serve).await {
                Ok(file) => (StatusCode::OK, Some(file)),
                Err(e) => {
                    error!("failed to open: \"{}\": {}", to_serve.to_string_lossy(), e);
                    (StatusCode::NOT_FOUND, None)
                }
            }
        }
    };

    let resp = http::Response::builder().status(status).body(())?;
    stream.send_response(resp).await?;

    if let Some(mut file) = to_serve {
        loop {
            let mut buf = BytesMut::with_capacity(4096 * 10);
            if file.read_buf(&mut buf).await? == 0 {
                break;
            }
            stream.send_data(buf.freeze()).await?;
        }
    }

    stream.finish().await?;
    Ok(())
}
