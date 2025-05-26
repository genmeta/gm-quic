use std::{io, sync::Arc};

use qbase::net::address::AbstractAddr;

use crate::QuicInterface;

pub trait ProductQuicInterface: Send + Sync {
    fn bind(&self, addr: AbstractAddr) -> io::Result<Arc<dyn QuicInterface>>;
}

impl<F, Q> ProductQuicInterface for F
where
    F: Fn(AbstractAddr) -> io::Result<Q> + Send + Sync,
    Q: QuicInterface + 'static,
{
    #[inline]
    fn bind(&self, addr: AbstractAddr) -> io::Result<Arc<dyn QuicInterface>> {
        Ok(Arc::new((self)(addr)?))
    }
}
