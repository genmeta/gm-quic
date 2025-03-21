use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use gm_quic::QuicClient;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// cargo run --example client -- \
///     --domain quit.test.net \
///     --root quic/examples/keychain/root/rootCA-ECC.crt \
///     --addr 127.0.0.1:4433
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Arguments {
    #[arg(long)]
    domain: String,
    #[arg(long)]
    addr: SocketAddr,
    #[clap(long, required = true)]
    root: PathBuf,
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
}

fn main() {
    let args = Arguments::parse();
    let code = {
        match run(args) {
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
async fn run(args: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let mut root_cert_store = rustls::RootCertStore::empty();

    let root = std::fs::read(args.root).expect("failed to read certificate file");
    let root_cert = match CertificateDer::from_pem_slice(&root) {
        Ok(root_cert) => vec![root_cert],
        Err(_) => vec![CertificateDer::from(root)],
    };

    root_cert_store.add_parsable_certificates(root_cert);

    let client = QuicClient::builder()
        .bind(args.bind)?
        .reuse_connection()
        .prefer_versions([0x00000001u32])
        .with_root_certificates(Arc::new(root_cert_store))
        .without_cert()
        .enable_sslkeylog()
        .with_alpns([b"hq-29".as_ref()].iter().map(|s| s.to_vec()))
        .build();

    let quic_conn = client.connect(args.domain, args.addr).unwrap();
    loop {
        let mut input = String::new();
        _ = std::io::stdin().read_line(&mut input).unwrap();

        let content = input.trim();
        if content.is_empty() {
            continue;
        }

        if content == "exit" || content == "quit" {
            quic_conn.close("Client close the connection".into(), 0);
            break;
        }

        let (_sid, (mut stream_reader, mut stream_writer)) = quic_conn
            .open_bi_stream()
            .await?
            .expect("very very hard to exhaust the available stream ids");
        tokio::spawn(async move {
            // 模拟发送一个请求
            let request = format!("GET {}\r\n", input.trim());
            eprintln!("Request: {request}");
            stream_writer.write_all(request.as_bytes()).await.unwrap();
            stream_writer.shutdown().await.unwrap();

            // 读取响应
            let mut response = String::new();
            let n = stream_reader.read_to_string(&mut response).await?;
            eprintln!("Response {n} bytes: {response}");
            Ok::<(), std::io::Error>(())
        });
    }
    Ok(())
}
