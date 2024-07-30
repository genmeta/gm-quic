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
}

#[cfg(test)]
mod tests {
    use futures::channel::mpsc;

    #[test]
    #[ignore = "no compile error means test pass"]
    fn macrro_expand() {
        type Item = ();

        #[derive(Clone, Copy)]
        struct Consumer;
        impl Consumer {
            fn consume(&self, _item: Item) {
                // do nothing
            }
        }

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
}
