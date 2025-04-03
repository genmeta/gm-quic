use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use gm_quic::{
    QuicServer, StreamReader, StreamWriter, ToCertificate, ToPrivateKey, handy::server_parameters,
};
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncWriteExt},
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    if let Err(error) = run().await {
        tracing::error!(?error, "server error");
        std::process::exit(1);
    };
}

pub type Error = Box<dyn std::error::Error + Send + Sync>;

async fn run() -> Result<(), Error> {
    let testcase = std::env::var("TESTCASE").expect("TESTCASE env var not set");

    let cert = fs::read("/cert/priv.key").await?.to_certificate();
    let key = fs::read("/cert/priv.key").await?.to_private_key();
    // let cert = include_bytes!("../../benchmark/certs/server_cert.pem").to_certificate();
    // let key = include_bytes!("../../benchmark/certs/server_key.pem").to_private_key();

    // TODO: chacha20 testcase
    let crypto_provider = rustls::crypto::ring::default_provider();

    let tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(cert, key)?;

    let server = QuicServer::builder_with_tls(tls_config)
        .with_parameters(server_parameters())
        .with_alpns(["hq-29"])
        .listen(&["[::1]:4433".parse()?, "127.0.0.1:4433".parse()?][..])?;

    match testcase.as_str() {
        "handshake" | "transfer" => serve_file_http09(server, ".").await,
        "http3" => serve_file_http3(server, ".").await,
        _ => std::process::exit(-127),
    }
}

pub async fn serve_file_http09<P>(server: Arc<QuicServer>, root: P) -> Result<(), Error>
where
    P: AsRef<Path> + Clone + Send + Sync + 'static,
{
    async fn serve_file(
        mut reader: StreamReader,
        mut writer: StreamWriter,
        root: impl AsRef<Path>,
    ) -> Result<(), Error> {
        let mut request = String::new();
        reader.read_to_string(&mut request).await?;

        // HTTP/0.9 is very simple - just a GET request with a path
        let serve = async {
            match request.trim().strip_prefix("GET /") {
                Some(path) => {
                    tracing::debug!(?path, "Received HTTP/0.9 request");
                    let mut file =
                        fs::File::open(PathBuf::from_iter([root.as_ref(), path.as_ref()])).await?;
                    io::copy(&mut file, &mut writer).await.map(|_| ())
                }
                None => Err(io::Error::other(format!(
                    "Invalid HTTP/0.9 request: {request}",
                ))),
            }
        };

        if let Err(error) = serve.await {
            tracing::warn!("failed to serve request: {}", error);
        }

        _ = writer.shutdown().await;

        Ok(())
    }

    loop {
        let (connection, _pathway) = server.accept().await?;
        let root = root.clone();
        tokio::spawn(async move {
            while let Ok(Some((_sid, (reader, writer)))) = connection.accept_bi_stream().await {
                tokio::spawn(serve_file(reader, writer, root.clone()));
            }
            Result::<(), Error>::Ok(())
        });
    }
}

pub async fn serve_file_http3<P>(server: Arc<QuicServer>, root: P) -> Result<(), Error>
where
    P: AsRef<Path> + Clone + Send + Sync + 'static,
{
    use bytes::Bytes;

    async fn serve_file<S>(
        request: http::Request<()>,
        mut request_stream: h3::server::RequestStream<S, Bytes>,
        root: impl AsRef<Path>,
    ) -> Result<(), Error>
    where
        S: for<'b> h3::quic::BidiStream<Bytes> + Send,
    {
        let (status, to_serve) = match request {
            req if req.method() != http::Method::GET => (http::StatusCode::FORBIDDEN, None),
            req if req.uri().path().contains("..") => (http::StatusCode::NOT_FOUND, None),
            req => match req.uri().path().trim().strip_prefix("/") {
                Some(path) => {
                    let to_serve = PathBuf::from_iter([root.as_ref(), path.as_ref()]);
                    (http::StatusCode::OK, Some(to_serve))
                }
                None => (http::StatusCode::NOT_FOUND, None),
            },
        };

        let resp = http::Response::builder().status(status).body(())?;

        let serve = async {
            request_stream.send_response(resp).await?;
            if let Some(to_serve) = to_serve {
                let mut file = fs::File::open(to_serve).await?;
                let mut buf = [0; 4096 * 10];
                loop {
                    let n = file.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    request_stream
                        .send_data(Bytes::copy_from_slice(&buf[..n]))
                        .await?;
                }
            }

            Result::<(), Error>::Ok(request_stream.finish().await?)
        };

        if let Err(error) = serve.await {
            tracing::error!(?error, "failed to serve file");
            _ = request_stream.finish().await;
            return Err(error);
        }

        Ok(())
    }

    loop {
        let (connection, _pathway) = server.accept().await?;
        let root = root.clone();
        tokio::spawn(async move {
            let mut connection: h3::server::Connection<h3_shim::QuicConnection, _> =
                h3::server::Connection::new(h3_shim::QuicConnection::new(connection).await).await?;
            while let Ok(Some((request, request_stream))) = connection.accept().await {
                tokio::spawn(serve_file(request, request_stream, root.clone()));
            }
            Result::<(), Error>::Ok(())
        });
    }
}
