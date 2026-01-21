use std::task::{Context, Poll, ready};

use crate::{BindUri, IO};

pub trait ProductIO: Send + Sync {
    fn bind(&self, bind_uri: BindUri) -> Box<dyn IO>;

    fn poll_rebind(&self, cx: &mut Context<'_>, quic_io: &mut Box<dyn IO>) -> Poll<()> {
        _ = ready!(quic_io.poll_close(cx));
        *quic_io = self.bind(quic_io.bind_uri());
        Poll::Ready(())
    }
}

pub trait ProductIoExt: ProductIO {
    fn rebind(&self, quic_io: &mut Box<dyn IO>) -> impl Future<Output = ()> {
        async { core::future::poll_fn(|cx| self.poll_rebind(cx, quic_io)).await }
    }
}

impl<F, Q> ProductIO for F
where
    F: Fn(BindUri) -> Q + Send + Sync,
    Q: IO + 'static,
{
    #[inline]
    fn bind(&self, bind_uri: BindUri) -> Box<dyn IO> {
        Box::new((self)(bind_uri))
    }
}
