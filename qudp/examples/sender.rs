use std::{
    future::Future,
    io::{self, IoSlice},
    iter,
    task::{ready, Poll},
};

use bytes::Bytes;
use qudp::{ArcController, SendHeader};

use std::task;

const MSG_SIZE: usize = 1200;
const MSG_COUNT: usize = 10_000;
const SEG_SIZE: Option<u16> = None;

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:0".parse().unwrap();
    let socket = ArcController::new(addr);
    let dst = "127.0.0.1:12345".parse().unwrap();

    let send_hdr = SendHeader {
        src: socket.local_addr(),
        dst,
        ttl: 64,
        ecn: None,
        seg_size: SEG_SIZE,
    };

    let sender = Sender {
        controller: socket,
        bufs: payloads(),
        hdr: send_hdr,
    };
    let ret = sender.await;
    match ret {
        Ok(n) => println!("sent {} bytes", n),
        Err(e) => println!("send failed: {}", e),
    }
}

fn payloads() -> Vec<Bytes> {
    let payload: Vec<u8> = iter::repeat(1u8).take(MSG_SIZE).collect();
    let payload = Bytes::from(payload);
    iter::repeat_with(|| payload.clone())
        .take(MSG_COUNT)
        .collect()
}

struct Sender {
    controller: ArcController,
    bufs: Vec<Bytes>,
    hdr: SendHeader,
}

impl Future for Sender {
    type Output = io::Result<usize>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let hdr = &this.hdr;
        let mut bufs = this
            .bufs
            .iter_mut()
            .map(|b| IoSlice::new(b))
            .collect::<Vec<_>>();

        let n = ready!(this.controller.poll_send(&mut bufs, hdr, cx))?;
        Poll::Ready(Ok(n))
    }
}
