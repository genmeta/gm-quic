pub mod handy;

use std::task::{Context, Poll, ready};

use crate::{Interface, logical::BindUri};

pub trait ProductQuicIO: Send + Sync {
    fn bind(&self, bind_uri: BindUri) -> Box<dyn Interface>;

    fn poll_rebind(&self, cx: &mut Context<'_>, quic_io: &mut Box<dyn Interface>) -> Poll<()> {
        _ = ready!(quic_io.poll_close(cx));
        *quic_io = self.bind(quic_io.bind_uri());
        Poll::Ready(())
    }
}

pub trait ProductQuicIoExt: ProductQuicIO {
    fn rebind(&self, quic_io: &mut Box<dyn Interface>) -> impl Future<Output = ()> {
        async { core::future::poll_fn(|cx| self.poll_rebind(cx, quic_io)).await }
    }
}

impl<F, Q> ProductQuicIO for F
where
    F: Fn(BindUri) -> Q + Send + Sync,
    Q: Interface + 'static,
{
    #[inline]
    fn bind(&self, bind_uri: BindUri) -> Box<dyn Interface> {
        Box::new((self)(bind_uri))
    }
}
