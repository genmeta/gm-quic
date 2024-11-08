use std::{net::SocketAddr, ops::Deref, path::PathBuf, sync::Arc};

use bytes::{Bytes, BytesMut};
use clap::Parser;
use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use http::{Request, StatusCode};
use tokio::{fs::File, io::AsyncReadExt};
use tracing::{error, info, trace_span};

#[derive(Parser, Debug)]
#[structopt(name = "server")]
struct Opt {
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    info!("serving {}", opt.root.display());
    let root = Arc::new(opt.root);
    if !root.is_dir() {
        return Err(format!("{}: is not a readable directory", root.display()).into());
    }
    let Certs { cert, key } = opt.certs;

    let quic_server = ::quic::QuicServer::buidler()
        .with_supported_versions([1u32])
        .without_cert_verifier()
        .enable_sni()
        .add_host_with_cert_files("localhost", cert, key)?
        .with_alpns([ALPN.to_vec()])
        .listen(&opt.listen[..])?;
    info!("listening on {:?}", opt.listen);

    // handle incoming connections and requests

    while let Ok((new_conn, _pathway)) = quic_server.accept().await {
        trace_span!("New connection being attempted");

        let root = root.clone();
        let mut h3_conn = h3::server::Connection::new(h3_shim::QuicConnection::new(new_conn).await)
            .await
            .unwrap();
        tokio::spawn(async move {
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
                            info!("request handled");
                        });
                    }

                    // indicating no more streams to be received
                    Ok(None) => {
                        break;
                    }

                    Err(err) => {
                        error!("error on accept {}", err);
                        match err.get_error_level() {
                            ErrorLevel::ConnectionError => break,
                            ErrorLevel::StreamError => continue,
                        }
                    }
                }
            }
        });
    }

    // shut down gracefully
    // wait for connections to be closed before exiting
    // endpoint.wait_idle().await;
    Ok(())
}

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

    let resp = http::Response::builder().status(status).body(()).unwrap();
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
    Ok(())
}
