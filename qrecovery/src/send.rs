pub mod sndbuf;

mod outgoing;
mod sender;
mod writer;

pub use outgoing::{IsCancelled, Outgoing};
pub use sender::ArcSender;
pub use writer::Writer;

pub fn new(wnd_size: u64) -> ArcSender {
    ArcSender::with_wnd_size(wnd_size)
}
