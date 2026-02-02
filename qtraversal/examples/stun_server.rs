use std::{io::Result, net::SocketAddr, sync::Arc};

use clap::Parser;
use qinterface::io::{IO, ProductIO, handy::DEFAULT_IO_FACTORY};
use qtraversal::{
    nat::{
        router::StunRouter,
        server::{StunServer, StunServerConfig},
    },
    route::{Forwarder, ReceiveAndDeliverPacket},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Arguments {
    #[arg(long, default_value = "127.0.0.1:20002")]
    pub bind_addr1: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:4433")]
    pub bind_addr2: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:20002")]
    pub change_addr: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:20002")]
    pub outer_addr1: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:20002")]
    pub outer_addr2: SocketAddr,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Arguments::parse();
    init_logger(&args)?;

    let factory: Arc<dyn ProductIO> = Arc::new(DEFAULT_IO_FACTORY);

    let bind_uri1 = format!("inet://{}", args.bind_addr1).into();
    let iface1: Arc<dyn IO> = Arc::from(factory.bind(bind_uri1));
    let stun_router1 = StunRouter::new();
    let _iface1_recv_task = ReceiveAndDeliverPacket::task()
        .stun_router(stun_router1.clone())
        .forwarder(Forwarder::Server {
            outer_addr: args.outer_addr1,
        })
        .iface_ref(iface1.clone())
        .spawn();

    let bind_uri2 = format!("inet://{}", args.bind_addr2).into();
    let iface2: Arc<dyn IO> = Arc::from(factory.bind(bind_uri2));
    let stun_router2 = StunRouter::new();
    let _iface2_recv_task = ReceiveAndDeliverPacket::task()
        .stun_router(stun_router2.clone())
        .forwarder(Forwarder::Server {
            outer_addr: args.outer_addr2,
        })
        .iface_ref(iface2.clone())
        .spawn();

    let server1 = StunServer::new(
        iface1,
        stun_router1,
        StunServerConfig::builder()
            .change_port(args.bind_addr2.port())
            .change_address(args.change_addr)
            .init(),
    );
    let server2 = StunServer::new(
        iface2,
        stun_router2,
        StunServerConfig::builder()
            .change_port(args.bind_addr1.port())
            .change_address(args.change_addr)
            .init(),
    );
    _ = tokio::try_join!(server1.spawn(), server2.spawn())?;
    Ok(())
}

fn init_logger(args: &Arguments) -> std::io::Result<()> {
    let log_name = args.bind_addr1.ip().to_string() + "-stun.log";
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_name)?;

    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_ansi(false)
                .with_writer(file),
        )
        .try_init();
    Ok(())
}
