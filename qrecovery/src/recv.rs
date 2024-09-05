mod incoming;
mod reader;
mod recver;

pub mod rcvbuf;

pub use incoming::{Incoming, IsStopped, UpdateWindow};
pub use reader::Reader;
pub use recver::ArcRecver;

pub fn new(buf_size: u64) -> ArcRecver {
    ArcRecver::new(buf_size)
}
