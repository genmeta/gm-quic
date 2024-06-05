use std::sync::{Arc, Mutex};

pub mod sndbuf;

mod outgoing;
mod sender;
mod writer;

pub use outgoing::{IsCancelled, Outgoing};
pub use sender::Sender;
pub use writer::Writer;

pub fn new(initial_max_stream_data: u64) -> (Outgoing, Writer) {
    let arc_sender = Arc::new(Mutex::new(Ok(Sender::with_buf_size(
        initial_max_stream_data,
    ))));
    let writer = Writer(arc_sender.clone());
    let outgoing = Outgoing(arc_sender);
    (outgoing, writer)
}
