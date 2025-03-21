use std::{io, net::SocketAddr};

use qinterface::QuicInterface;

pub trait ProductQuicInterface: Send + Sync {
    type QuicInterface: QuicInterface;

    fn bind(&self, addr: SocketAddr) -> io::Result<Self::QuicInterface>;
}

impl<F, Qi> ProductQuicInterface for F
where
    F: Fn(SocketAddr) -> io::Result<Qi> + Send + Sync,
    Qi: QuicInterface,
{
    type QuicInterface = Qi;

    #[inline]
    fn bind(&self, addr: SocketAddr) -> io::Result<Self::QuicInterface> {
        (self)(addr)
    }
}
