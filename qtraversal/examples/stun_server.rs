use std::{io::Result, net::SocketAddr, sync::Arc};

use clap::Parser;
use qtraversal::{
    iface::Interface,
    nat::{protocol, server::Server},
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
    let iface1 = Interface::new(
        args.bind_addr1,
        format!("inet://{}", args.bind_addr1).into(),
    )?;
    let iface2 = Interface::new(
        args.bind_addr2,
        format!("inet://{}", args.bind_addr2).into(),
    )?;
    iface1.set_outer_addr(args.outer_addr1);
    iface2.set_outer_addr(args.outer_addr2);

    let iface1 = Arc::new(iface1);
    let iface2 = Arc::new(iface2);
    let protocol1 = protocol::StunProtocol::new(iface1.clone());
    let protocol2 = protocol::StunProtocol::new(iface2.clone());
    let mut server = Server::new((Arc::new(protocol1), Arc::new(protocol2)), args.change_addr);
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
