mod incoming;
mod reader;
mod recver;

pub mod rcvbuf;

use std::sync::{Arc, Mutex};

pub use incoming::{Incoming, IsStopped, UpdateWindow};
pub use reader::Reader;
use recver::Recver;

pub fn new(initial_max_stream_data: u64) -> (Incoming, Reader) {
    let arc_recver = Arc::new(Mutex::new(Ok(Recver::new(initial_max_stream_data))));
    let reader = Reader::new(arc_recver.clone());
    let incoming = Incoming::new(arc_recver);
    (incoming, reader)
}
