use std::task::{Context, Poll, ready};

use crate::{
    QuicIO,
    logical::{BindUri, WeakInterface},
};

pub trait ProductQuicIO: Send + Sync {
    fn bind(&self, bind_uri: BindUri) -> Box<dyn QuicIO>;

    fn poll_rebind(&self, cx: &mut Context<'_>, quic_io: &mut Box<dyn QuicIO>) -> Poll<()> {
        _ = ready!(quic_io.poll_close(cx));
        *quic_io = self.bind(quic_io.bind_uri());
        Poll::Ready(())
    }

    /// Setup necessary tasks for the interface
    ///
    /// For example:
    /// - Monitoring network changes and trigger rebinds
    /// - Receiving quic packets and route them
    fn init(&self, weak_iface: &WeakInterface) {
        _ = weak_iface;
    }
}

pub trait ProductQuicIoExt: ProductQuicIO {
    fn rebind(&self, quic_io: &mut Box<dyn QuicIO>) -> impl Future<Output = ()> {
        async { core::future::poll_fn(|cx| self.poll_rebind(cx, quic_io)).await }
    }
}

impl<F, Q> ProductQuicIO for F
where
    F: Fn(BindUri) -> Q + Send + Sync,
    Q: QuicIO + 'static,
{
    #[inline]
    fn bind(&self, bind_uri: BindUri) -> Box<dyn QuicIO> {
        Box::new((self)(bind_uri))
    }
}
