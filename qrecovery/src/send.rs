use std::sync::{Arc, Mutex};

pub mod sndbuf;

mod outgoing;
mod sender;
mod writer;

pub use outgoing::{IsCancelled, Outgoing};
pub use sender::Sender;
pub use writer::Writer;

pub fn new(wnd_size: u64) -> (Outgoing, Writer) {
    let arc_sender = Arc::new(Mutex::new(Ok(Sender::with_wnd_size(wnd_size))));
    let writer = Writer(arc_sender.clone());
    let outgoing = Outgoing(arc_sender);
    (outgoing, writer)
}
