use std::io::IoSlice;

use clap::{command, Parser};
use qudp::{ArcUsc, PacketHeader};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value_t = String::from("127.0.0.1:0"))]
    src: String,

    #[arg(long, default_value_t = String::from("127.0.0.1:12345"))]
    dst: String,

    #[arg(long, default_value_t = 1200)]
    msg_size: usize,

    #[arg(long, default_value_t = 100)]
    msg_count: usize,

    #[arg(long, default_value_t = false)]
    gso: bool,
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let args = Args::parse();
    let addr = args.src.parse().unwrap();
    let socket = ArcUsc::new(addr).expect("failed to create socket");
    let dst = args.dst.parse().unwrap();

    let send_hdr = PacketHeader {
        src: socket.local_addr().expect("failed to get local addr"),
        dst,
        ttl: 64,
        ecn: Some(1),
        seg_size: args.msg_size as u16,
        gso: args.gso,
    };

    let payload = vec![8u8; args.msg_size];
    let payloads = vec![IoSlice::new(&payload[..]); args.msg_count];

    match socket.send(&payloads, send_hdr).await {
        Ok(n) => log::info!("sent {} packets, dest: {}", n, dst),
        Err(e) => log::error!("send failed: {}", e),
    }
}
