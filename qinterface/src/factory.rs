use std::{io, sync::Arc};

use qbase::net::address::VirtualAddr;

use crate::QuicInterface;

pub trait ProductQuicInterface: Send + Sync {
    fn bind(&self, addr: VirtualAddr) -> io::Result<Arc<dyn QuicInterface>>;
}

impl<F, Q> ProductQuicInterface for F
where
    F: Fn(VirtualAddr) -> io::Result<Q> + Send + Sync,
    Q: QuicInterface + 'static,
{
    #[inline]
    fn bind(&self, addr: VirtualAddr) -> io::Result<Arc<dyn QuicInterface>> {
        Ok(Arc::new((self)(addr)?))
    }
}
