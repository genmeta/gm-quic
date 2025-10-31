use std::{io::Result, net::SocketAddr, sync::Arc};

use clap::Parser;
use qinterface::local::Locations;
use qtraversal::{
    iface::Interface,
    nat::{client::Client, protocol::StunProtocol},
};
use tracing::info;
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Arguments {
    #[arg(long, default_value = "0.0.0.0:12345")]
    pub bind: SocketAddr,
    #[arg(long, default_value = "nat.genmeta.net:20004")]
    pub stun_svr: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    init_logger().unwrap();
    let args = Arguments::parse();
    let bind_uri = format!("inet://{}", args.bind);
    let iface =
        Arc::new(Interface::new(args.bind, bind_uri.into()).expect("failed to bind socket"));

    let stun_addr = tokio::net::lookup_host(&args.stun_svr)
        .await?
        .find(|addr| addr.is_ipv4() == args.bind.is_ipv4())
        .ok_or_else(|| std::io::Error::other("failed to resolve stun server"))?;

    let stun_protocol = StunProtocol::new(iface.clone());
    let client = Client::new(Arc::new(stun_protocol), stun_addr);
    let outer_addr = client.outer_addr().await.expect("failed to get outer addr");
    info!("Outer addr: {} Agent addr {}", outer_addr, stun_addr);
    // Ok(())
    let nat_type = client.nat_type().await;
    let mut observer = Locations::global().subscribe();
    while let Some(event) = observer.recv().await {
        info!("Location event: {:?}", event);
        info!("Nat type: {:?}", nat_type);
    }
    Ok(())

    // unreachable!("Observer never return None")
}

fn init_logger() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    Ok(())
}
