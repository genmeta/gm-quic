use std::{io, net::SocketAddr, sync::Arc};

use clap::Parser;
use qconnection::prelude::handy::server_parameters;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{Instrument, info, info_span};

#[derive(clap::Parser)]
struct Options {
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
}

#[tokio::main(flavor = "current_thread")]
#[allow(unused)]
pub async fn main() -> io::Result<()> {
    tracing_subscriber::fmt().init();

    let server = gm_quic::QuicServer::builder()
        .without_client_cert_verifier()
        .with_single_cert(
            include_bytes!("../../tests/keychain/localhost/server.cert"),
            include_bytes!("../../tests/keychain/localhost/server.key"),
        )
        .with_parameters(server_parameters())
        .listen(Options::parse().bind)?;

    info!("listen on {:?}", server.addresses());

    launch(server).await?;

    Ok(())
}

#[tracing::instrument(name = "server_listen", skip(server), ret)]
pub async fn launch(server: Arc<gm_quic::QuicServer>) -> io::Result<()> {
    #[tracing::instrument(name = "server_listen", skip(conn), ret)]
    async fn handle_connection(conn: Arc<gm_quic::Connection>, from: SocketAddr) -> io::Result<()> {
        loop {
            let (sid, (reader, writer)) = conn.accept_bi_stream().await?.unwrap();
            tokio::spawn(
                handle_stream(reader, writer).instrument(info_span!("handle_stream",%sid)),
            );
        }
    }

    async fn handle_stream(
        mut reader: gm_quic::StreamReader,
        mut writer: gm_quic::StreamWriter,
    ) -> io::Result<()> {
        let mut message = String::new();
        reader.read_to_string(&mut message).await?;

        writer.write_all(message.as_bytes()).await?;
        writer.shutdown().await?;

        io::Result::Ok(())
    }

    loop {
        let (connection, pathway) = server.accept().await?;
        info!(source = ?pathway.remote(), "accepted new connection");
        tokio::spawn(handle_connection(connection, *pathway.remote()));
    }
}
