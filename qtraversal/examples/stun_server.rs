use std::{io::Result, net::SocketAddr, sync::Arc};

use clap::Parser;
use qinterface::{
    Interface,
    factory::{ProductInterface, handy::DEFAULT_QUIC_IO_FACTORY},
};
use qtraversal::{
    nat::{router::StunRouter, server::StunServer},
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

    let bind_uri = format!("inet://{}", args.bind_addr1).into();
    let iface1: Arc<dyn Interface> = Arc::from(DEFAULT_QUIC_IO_FACTORY.bind(bind_uri));
    let stun_router1 = StunRouter::new();
    let forwarder1 = Forwarder::Server {
        outer_addr: args.outer_addr1,
    };
    let _iface1_recv_task = ReceiveAndDeliverPacket::task()
        .stun_routers(stun_router1.clone())
        .forwarder(forwarder1)
        .iface_ref(iface1.clone())
        .spawn();

    let bind_uri = format!("inet://{}", args.bind_addr2).into();
    let iface2: Arc<dyn Interface> = Arc::from(DEFAULT_QUIC_IO_FACTORY.bind(bind_uri));
    let stun_router2 = StunRouter::new();
    let forwarder2 = Forwarder::Server {
        outer_addr: args.outer_addr2,
    };
    let _iface2_recv_task = ReceiveAndDeliverPacket::task()
        .stun_routers(stun_router2.clone())
        .forwarder(forwarder2)
        .iface_ref(iface2.clone())
        .spawn();

    let mut server = StunServer::new(
        [(iface1, stun_router1), (iface2, stun_router2)],
        args.change_addr,
    );
    server.run().await?;
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
