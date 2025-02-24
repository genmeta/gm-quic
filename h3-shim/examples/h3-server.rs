use std::{net::SocketAddr, ops::Deref, path::PathBuf, sync::Arc};

use bytes::{Bytes, BytesMut};
use clap::Parser;
use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use http::{Request, StatusCode};
use qbase::param::ServerParameters;
use tokio::{fs::File, io::AsyncReadExt};
use tracing::{Instrument, error, info, info_span};

#[derive(Parser, Debug)]
#[structopt(name = "server")]
pub struct Opt {
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
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_ansi(true)
        .init();
    // console_subscriber::init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    // process cli arguments
    let opt = Opt::parse();

    run(opt).await
}

pub async fn run(opt: Opt) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("serving {}", opt.root.display());
    let root = Arc::new(opt.root);
    if !root.is_dir() {
        return Err(format!("{}: is not a readable directory", root.display()).into());
    }
    let Certs { cert, key } = opt.certs;

    let mut params = ServerParameters::default();

    params.set_initial_max_streams_bidi(100);
    params.set_initial_max_streams_uni(100);
    params.set_initial_max_data((1u32 << 20).into());
    params.set_initial_max_stream_data_uni((1u32 << 20).into());
    params.set_initial_max_stream_data_bidi_local((1u32 << 20).into());
    params.set_initial_max_stream_data_bidi_remote((1u32 << 20).into());

    let quic_server = ::gm_quic::QuicServer::builder()
        .with_supported_versions([1u32])
        .without_cert_verifier()
        .with_parameters(params)
        .enable_sni()
        .add_host("localhost", cert.as_path(), key.as_path())
        .with_alpns([ALPN.to_vec()])
        .listen(&opt.listen[..])?;
    info!("listening on {:?}", quic_server.addresses());

    // handle incoming connections and requests

    while let Ok((new_conn, _pathway)) = quic_server.accept().await {
        let root = root.clone();
        let Ok(mut h3_conn) =
            h3::server::Connection::new(h3_shim::QuicConnection::new(new_conn).await)
                .await
                .inspect_err(|e| error!("failed to create h3 connection: {}", e))
        else {
            continue;
        };
        tokio::spawn(
            async move {
                info!("new connection established");
                loop {
                    match h3_conn.accept().await {
                        Ok(Some((req, stream))) => {
                            info!("new request: {:#?}", req);

                            let root = root.clone();

                            tokio::spawn(async {
                                if let Err(e) = handle_request(req, stream, root).await {
                                    error!("handling request failed: {}", e);
                                }
                            });
                        }

                        // indicating no more streams to be received
                        Ok(None) => {
                            break;
                        }

                        Err(err) => {
                            error!("error on accept connection: {}", err);
                            match err.get_error_level() {
                                ErrorLevel::ConnectionError => break,
                                ErrorLevel::StreamError => continue,
                            }
                        }
                    }
                }
            }
            .instrument(info_span!("handle_connection")),
        );
    }

    // shut down gracefully
    // wait for connections to be closed before exiting
    // endpoint.wait_idle().await;
    Ok(())
}

#[tracing::instrument(skip_all)]
async fn handle_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
    serve_root: Arc<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    let (status, to_serve) = match serve_root.deref() {
        _ if req.uri().path().contains("..") => (StatusCode::NOT_FOUND, None),
        root => {
            let to_serve = root.join(req.uri().path().strip_prefix('/').unwrap_or(""));
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
    match stream.send_response(resp).await {
        Ok(_) => info!("successfully respond to connection"),
        Err(err) => error!("unable to send response to connection peer: {:?}", err),
    }

    if let Some(mut file) = to_serve {
        info!("serving file");
        loop {
            let mut buf = BytesMut::with_capacity(4096 * 10);
            if file.read_buf(&mut buf).await? == 0 {
                break;
            }
            stream.send_data(buf.freeze()).await?;
        }
        info!("all data written")
    }

    stream.finish().await?;
    info!("stream finished");
    Ok(())
}
