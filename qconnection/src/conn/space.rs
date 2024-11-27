pub mod data;
pub mod handshake;
pub mod initial;

use std::future::Future;

pub use data::{ClosingOneRttScope, DataSpace};
pub use handshake::{ClosingHandshakeScope, HandshakeSpace};
pub use initial::InitialSpace;
use qbase::{
    frame::{Frame, FrameReader},
    packet::{decrypt::decrypt_packet, header::GetType, DataPacket},
};
use tokio::sync::Notify;

pub trait RecvPacket {
    fn has_rcvd_ccf(&self, packet: DataPacket) -> bool;

    fn decrypt_and_parse(
        key: &dyn rustls::quic::PacketKey,
        pn: u64,
        mut packet: DataPacket,
        body_offset: usize,
    ) -> bool {
        decrypt_packet(key, pn, packet.bytes.as_mut(), body_offset).unwrap();
        let body = packet.bytes.split_off(body_offset);
        FrameReader::new(body.freeze(), packet.header.get_type())
            .filter_map(|frame| frame.ok())
            .any(|(f, _)| matches!(f, Frame::Close(_)))
    }
}

async fn any<F, T>(fut: F, notify: &Notify) -> Option<T>
where
    F: Future<Output = Option<T>>,
{
    tokio::select! {
        _ = notify.notified() => None,
        v = fut => v,
    }
}

#[macro_export]
macro_rules! pipe {
    (
        $input:ident |> $var:expr,$method:ident
    ) => {{
        #[allow(unused)]
        ::tokio::spawn({
            let mut input = $input;
            let mut owned_capture = ::std::clone::Clone::clone(&$var);
            async move {
                while let Some(item) = ::futures::stream::StreamExt::next(&mut input).await {
                    _ = owned_capture.$method(&item);
                }
            }
        })
    }};
    (
        $input:ident |> $($lambda:tt)*
    ) => {{
        #[allow(unused)]
        ::tokio::spawn({
            let mut input = $input;
            let mut lambda = $($lambda)*;
            async move {
                while let Some(item) = ::futures::stream::StreamExt::next(&mut input).await {
                    _ = lambda(&item);
                }
            }
        })
    }};
    (
        @error($error:expr)
        $input:ident |> $var:expr,$method:ident
    ) => {{
        #[allow(unused)]
        ::tokio::spawn({
            let mut input = $input;
            let mut owned_capture = ::std::clone::Clone::clone(&$var);
            let mut error = ::std::clone::Clone::clone($error);

            async move {
                while let Some(item) = ::futures::stream::StreamExt::next(&mut input).await {
                    if let Err(e) = owned_capture.$method(&item) {
                        $crate::error::ConnError::on_error(&error, e);
                        return;
                    }
                }
            }
        })
    }};
    (
        @error($error:expr)
        $input:ident |> $($lambda:tt)*
    ) => {{
        #[allow(unused)]
        ::tokio::spawn({
            let mut input = $input;
            let mut error = ::std::clone::Clone::clone($error);
            let mut lambda = $($lambda)*;
            async move {
                while let Some(item) = ::futures::stream::StreamExt::next(&mut input).await {
                    if let Err(e) = lambda(&item) {
                        $crate::error::ConnError::on_error(&error, e);
                        return;
                    }
                }
            }
        })
    }};
}

#[cfg(test)]
mod tests {
    use futures::{channel::mpsc, SinkExt};
    use qbase::error::{Error, ErrorKind};

    use crate::error::{ConnError, ConnErrorSource};

    #[derive(Clone, Copy)]
    struct Consumer;
    impl Consumer {
        fn consume(&self, _item: &()) {
            // do nothing
        }

        fn consume_return_ok(&self, _item: &()) -> Result<(), Error> {
            Ok(())
        }

        fn consume_return_error(&self, _item: &()) -> Result<(), Error> {
            Err(Error::with_default_fty(ErrorKind::Internal, "Test error"))
        }
    }

    #[tokio::test]
    async fn macro_expand() {
        let c = Consumer;
        let (mut tx, rx) = mpsc::unbounded::<()>();
        pipe!(
            rx |> c,consume
        );
        assert!(tx.send(()).await.is_ok());

        let c = (Consumer,);
        let (mut tx, rx) = mpsc::unbounded::<()>();
        pipe!(
            rx |> c.0,consume
        );
        assert!(tx.send(()).await.is_ok());

        let c = ((Consumer,),);
        let (mut tx, rx) = mpsc::unbounded::<()>();
        pipe!(
            rx |> c.0.0,consume
        );
        assert!(tx.send(()).await.is_ok());

        let c = (((Consumer,),),);
        let (mut tx, rx) = mpsc::unbounded::<()>();
        pipe!(
            rx |> c.0.0.0,consume
        );
        assert!(tx.send(()).await.is_ok());
    }

    #[tokio::test]
    async fn macro_expand2() {
        let c = Consumer;
        let error = &ConnError::default();

        let (mut tx1, rx1) = mpsc::unbounded::<()>();
        pipe!(
            @error(error)
            rx1 |> c,consume_return_ok
        );

        assert!(tx1.send(()).await.is_ok());
    }

    #[tokio::test]
    async fn macro_expand3() {
        let c = Consumer;
        let error = ConnError::default();

        let (mut tx1, rx1) = mpsc::unbounded::<()>();
        pipe!(
            @error(&error)
            rx1 |> c,consume_return_error
        );

        assert!(tx1.send(()).await.is_ok());
        let (_, kind) = error.await;
        assert_eq!(kind, ConnErrorSource::Transport);
        assert!(tx1.send(()).await.is_err());
    }
}
