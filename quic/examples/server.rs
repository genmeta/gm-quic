use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use quic::QuicServer;

// cargo run --example server -- \
//      --cert quic/examples/keychain/quic.test.net/quic-test-net-ECC.crt \
//      --key  quic/examples/keychain/quic.test.net/quic-test-net-ECC.key \
//      --bind 127.0.0.1:4433
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Opt {
    #[clap(long, required = true)]
    cert: PathBuf,
    #[clap(long, required = true)]
    key: PathBuf,
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
}

fn main() {
    let opt = Opt::parse();
    let code = {
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(options: Opt) -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let server = QuicServer::bind([options.bind], true)
        .with_supported_versions([0x00000001u32])
        .without_cert_verifier()
        .with_single_cert(options.cert, options.key)
        .listen()?;

    while let Ok((_conn, addr)) = server.accept().await {
        log::trace!("New connection from {}", addr);
    }
    Ok(())
}
