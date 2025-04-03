use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use gm_quic::{QuicClient, ToCertificate, handy::client_parameters};
use tokio::io::AsyncWriteExt;

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
    #[arg(long, default_values = ["0.0.0.0:0", "[::1]:0"])]
    bind: Vec<SocketAddr>,
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
    root_cert_store.add_parsable_certificates(options.root.to_certificate());

    let client = QuicClient::builder()
        .bind(options.bind.as_slice())?
        .reuse_connection()
        .prefer_versions([0x00000001u32])
        .with_root_certificates(Arc::new(root_cert_store))
        .without_cert()
        .with_parameters(client_parameters())
        .with_alpns([b"hq-29" as &[u8]])
        .enable_sslkeylog()
        .build();

    let quic_conn = client
        .connect(options.domain.clone(), options.addr)
        .unwrap();
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

        eprintln!("Sending request");
        let (_sid, (mut stream_reader, mut stream_writer)) = quic_conn
            .open_bi_stream()
            .await?
            .expect("very very hard to exhaust the available stream ids");
        // 模拟发送一个请求
        let request = format!("GET /{content}");
        eprintln!("Request: \n{request}");
        stream_writer.write_all(request.as_bytes()).await.unwrap();
        stream_writer.shutdown().await.unwrap();

        // 读取响应
        eprintln!("Response: \n");
        tokio::io::copy(&mut stream_reader, &mut tokio::io::stdout())
            .await
            .unwrap();
        eprintln!("\nResponse end");
    }
    Ok(())
}
