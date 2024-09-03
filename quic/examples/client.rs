use std::{fs::File, io::BufReader, net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use quic::QuicClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// cargo run --example client -- \
///     --domain quit.test.net \
///     --root quic/examples/keychain/root/rootCA-ECC.crt \
///     --addr 127.0.0.1:4433
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Arguments {
    #[arg(long)]
    keylog: bool,
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
        if let Err(e) = run(args) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(args: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_parsable_certificates(
        rustls_pemfile::certs(&mut BufReader::new(
            File::open(args.root).expect("Failed to open cert file"),
        ))
        .map(|cert| cert.expect("Failed to read and extract cert from the cert file")),
    );

    let client = QuicClient::bind([
        // "[2001:db8::1]:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    ])
    .reuse_connection()
    .enable_happy_eyeballs()
    .prefer_versions([0x00000001u32])
    .with_root_certificates(Arc::new(root_cert_store))
    .without_cert()
    .with_keylog(args.keylog)
    .with_alpn([b"hq-29".as_ref()].iter().map(|s| s.to_vec()))
    .build();

    let quic_conn = client.connect(args.domain, args.addr).unwrap();
    let quic_streams = quic_conn.streams()?;
    loop {
        let mut input = String::new();
        let _n = std::io::stdin().read_line(&mut input).unwrap();

        let content = input.trim();
        if content.is_empty() {
            continue;
        }

        if content == "exit" || content == "quit" {
            quic_conn.close("Client close the connection");
            break;
        }

        let (mut stream_reader, mut stream_writer) = quic_streams
            .open_bi()
            .await?
            .expect("very very hard to exhaust the available stream ids");
        tokio::spawn(async move {
            // 模拟发送一个请求
            let request = format!("GET {} HTTP/1.1\r\n", input.trim());
            stream_writer.write_all(request.as_bytes()).await.unwrap();

            // 读取响应
            let mut response = [0u8; 1024];
            loop {
                let n = stream_reader.read(&mut response[..]).await?;
                if n == 0 {
                    break;
                }

                eprint!("Response: {:?}", &response[..n]);
            }
            Ok::<(), std::io::Error>(())
        });
    }
    Ok(())
}
