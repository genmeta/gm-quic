pub mod handy;

use std::io;

use qbase::net::addr::BindUri;

use crate::QuicIO;

pub trait ProductQuicIO: Send + Sync {
    fn bind(&self, bind_uri: BindUri) -> io::Result<Box<dyn QuicIO>>;
}

impl<F, Q> ProductQuicIO for F
where
    F: Fn(BindUri) -> io::Result<Q> + Send + Sync,
    Q: QuicIO + 'static,
{
    #[inline]
    fn bind(&self, bind_uri: BindUri) -> io::Result<Box<dyn QuicIO>> {
        Ok(Box::new((self)(bind_uri)?))
    }
}
