use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use gm_quic::QuicServer;

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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();
    run(Options::parse())
        .await
        .inspect_err(|error| tracing::error!(?error))
}

async fn run(options: Options) -> Result<(), Box<dyn std::error::Error>> {
    let server = QuicServer::builder()
        .with_supported_versions([0x00000001u32])
        .without_client_cert_verifier()
        .with_single_cert(options.cert.as_path(), options.key.as_path())
        .listen(options.bind)?;

    while let Ok((_conn, pathway)) = server.accept().await {
        tracing::info!("New connection from {:?}", pathway.remote());
    }
    Ok(())
}
