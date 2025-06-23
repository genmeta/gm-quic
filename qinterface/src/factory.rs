use std::io;

use qbase::net::address::BindAddr;

use crate::QuicIO;

pub trait ProductQuicIO: Send + Sync {
    fn bind(&self, addr: BindAddr) -> io::Result<Box<dyn QuicIO>>;
}

impl<F, Q> ProductQuicIO for F
where
    F: Fn(BindAddr) -> io::Result<Q> + Send + Sync,
    Q: QuicIO + 'static,
{
    #[inline]
    fn bind(&self, addr: BindAddr) -> io::Result<Box<dyn QuicIO>> {
        Ok(Box::new((self)(addr)?))
    }
}
