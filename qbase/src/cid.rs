mod connection_id;
pub use connection_id::*;

mod local_cid;
pub use local_cid::*;

mod remote_cid;
pub use remote_cid::*;

/// Connection ID registry.
///
/// - `local` represents the management of connection IDs issued by me to peer,
/// - `remote` represents the reception of connection IDs issued by peer,
///    which will be used by the path.
#[derive(Debug, Clone)]
pub struct Registry<LOCAL, REMOTE> {
    pub local: LOCAL,
    pub remote: REMOTE,
}

impl<LOCAL, REMOTE> Registry<LOCAL, REMOTE> {
    /// Create a new connection ID registry.
    pub fn new(local: LOCAL, remote: REMOTE) -> Self {
        Self { local, remote }
    }
}
