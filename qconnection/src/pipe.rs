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
        @trigger($trigger:expr)
        $from:ident |> $var:expr,$method:ident
    ) => {{
        #[allow(unused)]
        ::tokio::spawn({
            let mut from = $from;
            let mut catch = ::std::clone::Clone::clone(&$var);
            let mut trigger = ::std::clone::Clone::clone($trigger);
            async move {
                while let Some(item) = ::futures::stream::StreamExt::next(&mut from).await {
                    if let Err(e) = catch.$method(item) {
                        $crate::connection::ConnErrorTrigger::transmit_error(&trigger, e);
                    }
                }
            }
        })
    }};
}

#[cfg(test)]
mod tests {
    use futures::channel::mpsc;
    use qbase::error::Error;

    use crate::connection::ConnErrorTrigger;

    type Item = ();

    #[derive(Clone, Copy)]
    struct Consumer;
    impl Consumer {
        fn consume(&self, _item: Item) {
            // do nothing
        }

        fn consume_return_result(&self, _item: Item) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    #[ignore = "no compile error means test pass"]
    fn macro_expand() {
        let c = Consumer;
        let (_tx, rx) = mpsc::unbounded::<Item>();
        pipe!(
            rx |> c,consume
        );
        let c = (Consumer,);
        let (_tx, rx) = mpsc::unbounded::<Item>();
        pipe!(
            rx |> c.0,consume
        );

        let c = ((Consumer,),);
        let (_tx, rx) = mpsc::unbounded::<Item>();
        pipe!(
            rx |> c.0.0,consume
        );

        let c = (((Consumer,),),);
        let (_tx, rx) = mpsc::unbounded::<Item>();
        pipe!(
            rx |> c.0.0.0,consume
        );
    }

    #[test]

    fn macro_expand2() {
        let c = Consumer;
        let trigger = ConnErrorTrigger::new();
        let (_tx, rx) = mpsc::unbounded::<Item>();
        pipe!(
            @trigger(&trigger)
            rx |> c,consume_return_result
        );
    }
}
