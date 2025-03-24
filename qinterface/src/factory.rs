use std::{io, net::SocketAddr, sync::Arc};

use crate::QuicInterface;

pub trait ProductQuicInterface: Send + Sync {
    fn bind(&self, addr: SocketAddr) -> io::Result<Arc<dyn QuicInterface>>;
}

impl<F, Q> ProductQuicInterface for F
where
    F: Fn(SocketAddr) -> io::Result<Q> + Send + Sync,
    Q: QuicInterface + 'static,
{
    #[inline]
    fn bind(&self, addr: SocketAddr) -> io::Result<Arc<dyn QuicInterface>> {
        Ok(Arc::new((self)(addr)?))
    }
}
