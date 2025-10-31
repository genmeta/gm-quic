use std::{io, net::SocketAddr, sync::Arc};

use clap::Parser;
use gm_quic::{
    prelude::{Connection, ParameterId, QuicListeners, StreamReader, StreamWriter},
    qbase::param::ServerParameters,
    qtraversal,
};
use qtraversal::iface::TraversalFactory;
use tokio::io::AsyncWriteExt;
use tracing::{Instrument, info, info_span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(clap::Parser)]
struct Options {
    #[arg(long, default_value = "192.168.1.4:6000")]
    bind1: SocketAddr,
    #[arg(long, default_value = "[2409:8a00:1850:be40:1037:3cbd:ec40:11c6]:6000")]
    bind2: SocketAddr,
    #[arg(long, default_value = "nat.genmeta.net:20004")]
    stun_server: String,
}

#[tokio::main]
pub async fn main() -> io::Result<()> {
    init_logger()?;
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_panic(info);
        info!("panic: {}", info);
        std::process::exit(1);
    }));
    let ops = Options::parse();

    let stun_servers: Vec<SocketAddr> = tokio::net::lookup_host(&ops.stun_server).await?.collect();
    if stun_servers.is_empty() {
        return Err(io::Error::other("failed to resolve stun server"));
    }

    let factory = TraversalFactory::initialize_global(stun_servers).unwrap();
    let server = QuicListeners::builder()?
        // .with_single_cert(
        //     include_bytes!("../../../tests/keychain/localhost/server.cert"),
        //     include_bytes!("../../../tests/keychain/localhost/server.key"),
        // )
        .with_iface_factory(factory.as_ref().clone())
        .with_parameters(server_stream_unlimited_parameters())
        .without_client_cert_verifier()
        .listen(1000);

    server
        .add_server(
            "localhost",
            include_bytes!("../../../tests/keychain/localhost/server.cert"),
            include_bytes!("../../../tests/keychain/localhost/server.key"),
            [ops.bind1],
            None,
        )
        .await?;

    launch(server).await?;

    Ok(())
}

pub fn server_stream_unlimited_parameters() -> ServerParameters {
    let mut params = ServerParameters::default();
    _ = params.set(ParameterId::ActiveConnectionIdLimit, 10u32);
    _ = params.set(ParameterId::InitialMaxData, 1u32 << 20);
    _ = params.set(ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 20);
    _ = params.set(ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 20);
    _ = params.set(ParameterId::InitialMaxStreamDataUni, 1u32 << 20);
    _ = params.set(ParameterId::InitialMaxStreamsBidi, 100u32);
    _ = params.set(ParameterId::InitialMaxStreamsUni, 100u32);
    params
}

pub async fn launch(server: Arc<QuicListeners>) -> io::Result<()> {
    async fn handle_connection(conn: Arc<Connection>) -> io::Result<()> {
        loop {
            let (sid, (reader, writer)) = conn.accept_bi_stream().await?;
            tokio::spawn(
                handle_stream(reader, writer).instrument(info_span!("handle_stream",%sid)),
            );
        }
    }

    async fn handle_stream(mut reader: StreamReader, mut writer: StreamWriter) -> io::Result<()> {
        tokio::io::copy(&mut reader, &mut writer).await?;
        writer.shutdown().await?;
        tracing::info!("stream copy done");

        io::Result::Ok(())
    }

    loop {
        let (connection, _name, pathway, _link) = server
            .accept()
            .await
            .map_err(|_e| io::Error::other("accept error"))?;
        info!(source = ?pathway.remote(), "accepted new connection");
        tokio::spawn(handle_connection(Arc::new(connection)));
    }
}

pub fn init_logger() -> std::io::Result<()> {
    let filter = tracing_subscriber::filter::filter_fn(|metadata| {
        !metadata.target().contains("netlink_packet_route")
    });

    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::Layer::with_filter(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_ansi(false)
                .with_file(true)
                .with_line_number(true),
            filter,
        ))
        .try_init();
    Ok(())
}
