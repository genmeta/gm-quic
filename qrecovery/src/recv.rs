mod incoming;
mod reader;
mod recver;

pub mod rcvbuf;

use std::sync::{Arc, Mutex};

pub use incoming::{Incoming, IsStopped, UpdateWindow};
pub use reader::Reader;
use recver::Recver;

pub fn new(buf_size: u64) -> (Incoming, Reader) {
    let arc_recver = Arc::new(Mutex::new(Ok(Recver::new(buf_size))));
    let reader = Reader::new(arc_recver.clone());
    let incoming = Incoming::new(arc_recver);
    (incoming, reader)
}
