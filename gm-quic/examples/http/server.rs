use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use gm_quic::{Connection, QuicServer, StreamReader, StreamWriter};
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncWriteExt},
};

// cargo run --package gm-quic --example server -- \
//      --cert test/keychain/quic.test.net/quic-test-net-ECC.crt \
//      --key  test/keychain/quic.test.net/quic-test-net-ECC.key \
//      --bind 127.0.0.1:4433
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Options {
    #[clap(long, required = true)]
    cert: PathBuf,
    #[clap(long, required = true)]
    key: PathBuf,
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
}

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt().init();
    if let Err(error) = run(Options::parse()).await {
        tracing::info!(?error, "server error");
        panic!("{error:?}");
    }
}

async fn run(options: Options) -> Result<(), Error> {
    let server = QuicServer::builder()
        .with_supported_versions([0x00000001u32])
        .without_client_cert_verifier()
        .with_single_cert(options.cert.as_path(), options.key.as_path())
        .listen(options.bind)?;

    loop {
        let (connection, _pathway) = server.accept().await?;
        tokio::spawn(handle_connection(connection));
    }
}

async fn serve_file(mut reader: StreamReader, mut writer: StreamWriter) -> Result<(), Error> {
    let mut request = String::new();
    reader.read_to_string(&mut request).await?;

    // HTTP/0.9 is very simple - just a GET request with a path
    let serve = async {
        match request.trim().strip_prefix("GET /") {
            Some(path) => {
                tracing::debug!(?path, "Received HTTP/0.9 request");
                let mut file = fs::File::open(PathBuf::from_iter(["./", path])).await?;
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
async fn handle_connection(connection: Arc<Connection>) -> Result<(), Error> {
    loop {
        let (_sid, (reader, writer)) = connection.accept_bi_stream().await?.expect("unreachable");
        tokio::spawn(serve_file(reader, writer));
    }
}
