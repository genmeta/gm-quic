use std::{io, net::SocketAddr};

use clap::Parser;
use gm_quic::ToCertificate;
use rustls::RootCertStore;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tracing::info;

#[derive(Parser)]
struct Options {
    #[arg(long)]
    server: SocketAddr,
}

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> io::Result<()> {
    tracing_subscriber::fmt().init();

    let server_addr = Options::parse().server;

    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(include_bytes!("keychain/localhost/ca.cert").to_certificate());

    let client = gm_quic::QuicClient::builder()
        .with_root_certificates(roots)
        .without_cert()
        .with_parameters(client_stream_unlimited_parameters())
        .build();

    let connection = client.connect("localhost", server_addr)?;

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();

    loop {
        let (sid, (mut reader, mut writer)) = connection.open_bi_stream().await?.unwrap();
        info!(%sid, "opened bidi stream");

        stdout.write_all(b">").await?;
        stdout.flush().await?;

        let mut line = String::new();
        stdin.read_line(&mut line).await?;
        let line = line.trim();

        writer.write_all(line.as_bytes()).await?;
        writer.shutdown().await?;

        let mut echo = String::new();
        reader.read_to_string(&mut echo).await?;
        info!("server echoed: `{echo}`");
    }
}

fn client_stream_unlimited_parameters() -> gm_quic::ClientParameters {
    let mut params = gm_quic::ClientParameters::default();

    params.set_initial_max_streams_bidi(100u32);
    params.set_initial_max_streams_uni(100u32);
    params.set_initial_max_data(1u32 << 20);
    params.set_initial_max_stream_data_uni(1u32 << 20);
    params.set_initial_max_stream_data_bidi_local(1u32 << 20);
    params.set_initial_max_stream_data_bidi_remote(1u32 << 20);

    params
}
