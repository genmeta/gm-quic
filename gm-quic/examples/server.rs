use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use gm_quic::QuicServer;

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
        match run(opt) {
            Err(e) => {
                eprintln!("ERROR: {e}");
                1
            }
            _ => 0,
        }
    };
    ::std::process::exit(code);
}

#[tokio::main(flavor = "current_thread")]
async fn run(options: Opt) -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let server = QuicServer::builder()
        .with_supported_versions([0x00000001u32])
        .without_cert_verifier()
        // .keep_alive()
        .with_single_cert(options.cert.as_path(), options.key.as_path())
        .listen(options.bind)?;

    while let Ok((_conn, pathway)) = server.accept().await {
        log::trace!("New connection from {:?}", pathway.remote());
    }
    Ok(())
}
