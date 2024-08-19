mod connection_id;
pub use connection_id::*;

mod local_cid;
pub use local_cid::*;

mod remote_cid;
pub use remote_cid::*;

#[derive(Debug, Clone)]
pub struct Registry<LOCAL, REMOTE> {
    pub local: LOCAL,
    pub remote: REMOTE,
}

impl<LOCAL, REMOTE> Registry<LOCAL, REMOTE> {
    pub fn new(local: LOCAL, remote: REMOTE) -> Self {
        Self { local, remote }
    }
}
