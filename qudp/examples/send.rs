use std::io::IoSlice;

use clap::{Parser, command};
use qudp::{PacketHeader, UdpSocketController};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value_t = String::from("[::]:0"))]
    src: String,

    #[arg(long, default_value_t = String::from("[::1]:12345"))]
    dst: String,

    #[arg(long, default_value_t = 1200)]
    msg_size: usize,

    #[arg(long, default_value_t = 100)]
    msg_count: usize,

    #[arg(long, default_value_t = false)]
    gso: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let args = Args::parse();
    let addr = args.src.parse().unwrap();
    let socket = UdpSocketController::new(addr).expect("failed to create socket");
    let dst = args.dst.parse().unwrap();

    let send_hdr = PacketHeader::new(
        socket.local_addr().expect("failed to get local addr"),
        dst,
        64,
        None,
        args.msg_size as u16,
    );

    let payload = vec![8u8; args.msg_size];
    let payloads = vec![IoSlice::new(&payload[..]); args.msg_count];

    match socket.send(&payloads, send_hdr).await {
        Ok(n) => log::info!("sent {} packets, dest: {}", n, dst),
        Err(e) => log::error!("send failed: {}", e),
    }
}
