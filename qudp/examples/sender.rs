use std::{
    future::Future,
    io::{self, IoSlice},
    iter,
    task::{ready, Poll},
};

use bytes::Bytes;
use clap::{command, Parser};

use qudp::{ArcUsc, PacketHeader};

use std::task;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value_t = String::from("[::]:0"))]
    src: String,

    #[arg(long, default_value_t = String::from("[::1]:12345"))]
    dst: String,

    #[arg(long, default_value_t = 1200)]
    msg_size: usize,

    #[arg(long, default_value_t = 10)]
    msg_count: usize,

    #[arg(long, default_value_t = false)]
    gso: bool,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();
    let addr = args.src.parse().unwrap();
    let socket = ArcUsc::new(addr);
    let dst = args.dst.parse().unwrap();

    let send_hdr = PacketHeader {
        src: socket.local_addr(),
        dst,
        ttl: 64,
        ecn: Some(1),
        seg_size: args.msg_size as u16,
        gso: args.gso,
    };

    let sender = Sender {
        controller: socket,
        bufs: payloads(&args),
        hdr: send_hdr,
    };
    let ret = sender.await;
    match ret {
        Ok(n) => println!("sent {} bytes", n),
        Err(e) => println!("send failed: {}", e),
    }
}

fn payloads(args: &Args) -> Vec<Bytes> {
    let payload: Vec<u8> = iter::repeat(1u8).take(args.msg_size).collect();
    let payload = Bytes::from(payload);
    iter::repeat_with(|| payload.clone())
        .take(args.msg_count)
        .collect()
}

struct Sender {
    controller: ArcUsc,
    bufs: Vec<Bytes>,
    hdr: PacketHeader,
}

impl Future for Sender {
    type Output = io::Result<usize>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let hdr = &this.hdr;
        let bufs = this
            .bufs
            .iter_mut()
            .map(|b| IoSlice::new(b))
            .collect::<Vec<_>>();

        let n = ready!(this.controller.poll_send(&bufs, hdr, cx))?;
        Poll::Ready(Ok(n))
    }
}
