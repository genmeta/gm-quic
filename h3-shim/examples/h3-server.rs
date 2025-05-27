use std::{net::SocketAddr, ops::Deref, path::PathBuf, sync::Arc};

use bytes::{Bytes, BytesMut};
use clap::Parser;
use gm_quic::{Host, handy::server_parameters};
use h3::{quic::BidiStream, server::RequestStream};
use http::{Request, StatusCode};
use qevent::telemetry::handy::{DefaultSeqLogger, NullLogger};
use tokio::{fs::File, io::AsyncReadExt};

#[derive(Parser, Debug)]
#[command(name = "server")]
struct Options {
    #[arg(
        name = "dir",
        short,
        long,
        help = "Root directory of the files to serve. \
                If omitted, server will respond OK.",
        default_value = "./"
    )]
    root: PathBuf,
    #[arg(long, help = "Save the qlog to a dir", value_name = "PATH")]
    qlog: Option<PathBuf>,
    #[arg(
        short,
        long,
        value_delimiter = ',',
        default_values = ["127.0.0.1:4433", "[::1]:4433"],
        help = "What address:port to listen for new connections"
    )]
    listen: Vec<SocketAddr>,
    #[arg(
        long,
        short,
        value_delimiter = ',',
        default_value = "h3",
        help = "ALPNs to use for the connection"
    )]
    alpns: Vec<Vec<u8>>,
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

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(true)
        .init();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        // default value 512 out of macos ulimit
        .max_blocking_threads(256)
        .build()
        .expect("failed to build tokio runtime");

    if let Err(error) = rt.block_on(run(Options::parse())) {
        tracing::info!(?error, "server error");
        std::process::exit(1);
    }
}

async fn run(options: Options) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("serving {}", options.root.display());
    let root = Arc::new(options.root);
    if !root.is_dir() {
        return Err(format!("{}: is not a readable directory", root.display()).into());
    }

    let qlogger: Arc<dyn qevent::telemetry::Log + Send + Sync> = match options.qlog {
        Some(dir) => Arc::new(DefaultSeqLogger::new(dir)),
        None => Arc::new(NullLogger),
    };

    let Certs {
        server_name,
        cert,
        key,
    } = options.certs;

    let listeners = ::gm_quic::QuicListeners::builder()?
        .with_qlog(qlogger)
        .without_client_cert_verifier()
        .with_parameters(server_parameters())
        .add_host(
            server_name,
            Host::with_cert_key(cert.as_path(), key.as_path())?
                .bind_addresses(options.listen.as_slice())?,
        )?
        .with_alpns(options.alpns)
        .listen(128)?;
    tracing::info!("listen {:?}", listeners.hosts());

    // handle incoming connections and requests
    while let Ok((_server, new_conn, _pathway, _link)) = listeners.accept().await {
        let h3_conn =
            match h3::server::Connection::new(h3_shim::QuicConnection::new(new_conn)).await {
                Ok(h3_conn) => {
                    tracing::info!("accept a new quic connection");
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

async fn handle_connection<T>(
    serve_root: Arc<PathBuf>,
    mut connection: h3::server::Connection<T, Bytes>,
) where
    T: h3::quic::Connection<Bytes> + 'static,
    <T as h3::quic::OpenStreams<Bytes>>::BidiStream: h3::quic::BidiStream<Bytes> + Send + 'static,
{
    loop {
        match connection.accept().await {
            Ok(Some(request_resolver)) => {
                let serve_root = serve_root.clone();
                let handle_request = async move {
                    let (request, stream) = request_resolver.resolve_request().await?;
                    handle_request(request, stream, serve_root).await
                };
                tokio::spawn(async move {
                    if let Err(e) = handle_request.await {
                        tracing::error!("handling request failed: {}", e);
                    }
                });
            }
            Ok(None) => break,
            Err(..) => break,
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
                    tracing::error!("failed to open: \"{}\": {}", to_serve.to_string_lossy(), e);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {}
}
