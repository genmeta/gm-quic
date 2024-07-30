#[macro_export]
macro_rules! pipe {
    (
        $from:ident |> $var:expr,$method:ident
    ) => {{
        #[allow(unused)]
        ::tokio::spawn({
            let mut from = $from;
            let mut catch = ::std::clone::Clone::clone(&$var);
            async move {
                while let Some(item) = ::futures::stream::StreamExt::next(&mut from).await {
                    _ = catch.$method(item);
                }
            }
        })
    }};
    (
        @error($error:expr)
        $from:ident |> $var:expr,$method:ident
    ) => {{
        #[allow(unused)]
        ::tokio::spawn({
            let mut from = $from;
            let mut catch = ::std::clone::Clone::clone(&$var);
            let mut error = ::std::clone::Clone::clone(&$error);
            async move {
                while let Some(item) = ::futures::stream::StreamExt::next(&mut from).await {
                    if let Err(e) = catch.$method(item) {
                        $crate::connection::ConnError::on_error(&error, e);
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

    use crate::connection::ConnError;

    #[derive(Clone, Copy)]
    struct Consumer;
    impl Consumer {
        fn consume(&self, _item: ()) {
            // do nothing
        }

        fn consume_return_ok(&self, _item: ()) -> Result<(), Error> {
            Ok(())
        }

        fn consume_return_error(&self, _item: ()) -> Result<(), Error> {
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
        let error = ConnError::new();

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
        let error = ConnError::new();

        let (mut tx1, rx1) = mpsc::unbounded::<()>();
        pipe!(
            @error(error)
            rx1 |> c,consume_return_error
        );

        assert!(tx1.send(()).await.is_ok());
        let (_e, is_active) = error.error_occur().await;
        assert!(is_active);
        assert!(tx1.send(()).await.is_err());
    }
}
