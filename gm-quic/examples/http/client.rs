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
struct Options {
    #[arg(long)]
    domain: String,
    #[arg(long)]
    addr: SocketAddr,
    #[clap(long, required = true)]
    root: PathBuf,
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
    let mut root_cert_store = rustls::RootCertStore::empty();

    let root = std::fs::read(options.root).expect("failed to read certificate file");
    let root_cert = match CertificateDer::from_pem_slice(&root) {
        Ok(root_cert) => vec![root_cert],
        Err(_) => vec![CertificateDer::from(root)],
    };

    root_cert_store.add_parsable_certificates(root_cert);

    let client = QuicClient::builder()
        .bind(options.bind)?
        .reuse_connection()
        .prefer_versions([0x00000001u32])
        .with_root_certificates(Arc::new(root_cert_store))
        .without_cert()
        .enable_sslkeylog()
        .with_alpns([b"hq-29".as_ref()].iter().map(|s| s.to_vec()))
        .build();

    let quic_conn = client.connect(options.domain, options.addr).unwrap();
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
