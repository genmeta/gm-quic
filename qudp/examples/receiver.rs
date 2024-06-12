use std::{
    future::Future,
    io::{self, IoSliceMut},
    pin::Pin,
    task::{self, ready, Poll},
};

#[cfg(not(target_os = "linux"))]
const BATCH_SIZE: usize = 1;

#[cfg(target_os = "linux")]
const BATCH_SIZE: usize = 64;

const BUFFER_SIZE: usize = 1200;

use qudp::{ArcController, RecvHeader};

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:12345".parse().unwrap();
    let socket = ArcController::new(addr);
    let mut count = 0;
    loop {
        let receiver = Receiver {
            controller: socket.clone(),
            bufs: (0..BATCH_SIZE)
                .map(|_| [0u8; BUFFER_SIZE].to_vec())
                .collect::<Vec<_>>(),
            hdrs: (0..BATCH_SIZE)
                .map(|_| RecvHeader::default())
                .collect::<Vec<_>>(),
        };

        match receiver.await {
            Ok(n) => {
                count += n;
                println!("received {} bytes, total {}", n, count);
            }
            Err(e) => {
                println!("receiver error: {}", e);
                break;
            }
        }
    }
}

struct Receiver {
    controller: ArcController,
    bufs: Vec<Vec<u8>>,
    hdrs: Vec<RecvHeader>,
}

impl Future for Receiver {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let hdrs = &mut this.hdrs;

        let mut bufs = this
            .bufs
            .iter_mut()
            .map(|b| IoSliceMut::new(b))
            .collect::<Vec<_>>();

        let ret = ready!(this.controller.poll_recv(&mut bufs, hdrs, cx))?;

        let mut n = 0;
        hdrs.iter().take(ret).for_each(|h| n += h.seg_size);
        Poll::Ready(Ok(n))
    }
}
