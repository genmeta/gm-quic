pub mod handy;

use std::{
    collections::HashMap,
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use handy::NullExporter;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{Event, GroupID, VantagePointType};

pub trait Log {
    fn new_trace(&self, vantage_point: VantagePointType, group_id: GroupID) -> Span;
}

pub trait ExportEvent: Send + Sync {
    fn emit(&self, event: Event);

    fn filter_event(&self, scheme: &'static str) -> bool {
        _ = scheme;
        true
    }

    fn filter_raw_data(&self) -> bool {
        false
    }
}

pub mod filter {
    #[inline]
    #[cfg(feature = "enabled")]
    pub fn event(scheme: &'static str) -> bool {
        super::current_span::CURRENT_SPAN.with(|span| span.borrow().filter_event(scheme))
    }

    #[inline]
    #[cfg(not(feature = "enabled"))]
    pub fn event(_scheme: &'static str) -> bool {
        false
    }

    #[inline]
    #[cfg(all(feature = "enabled", feature = "raw_data"))]
    pub fn raw_data() -> bool {
        super::current_span::CURRENT_SPAN.with(|span| span.borrow().filter_raw_data())
    }

    #[inline]
    #[cfg(not(all(feature = "enabled", feature = "raw_data")))]
    pub fn raw_data() -> bool {
        false
    }
}

#[derive(Clone)]
pub struct Span {
    exporter: Arc<dyn ExportEvent>,
    fields: Arc<HashMap<&'static str, Value>>,
}

impl Debug for Span {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Span")
            .field("fields", &self.fields)
            .field("broker", &"..")
            .finish()
    }
}

impl Span {
    #[inline]
    pub fn new(exporter: Arc<dyn ExportEvent>, fields: HashMap<&'static str, Value>) -> Self {
        Self {
            exporter,
            fields: Arc::new(fields),
        }
    }

    #[inline]
    pub fn emit(&self, event: Event) {
        self.exporter.emit(event);
    }

    #[inline]
    pub fn filter_event(&self, scheme: &'static str) -> bool {
        self.exporter.filter_event(scheme)
    }

    #[inline]
    pub fn filter_raw_data(&self) -> bool {
        self.exporter.filter_raw_data()
    }

    #[inline]
    pub fn load<T: DeserializeOwned>(&self, name: &'static str) -> T {
        serde_json::from_value(self.fields[name].clone()).unwrap()
    }

    #[inline]
    pub fn try_load<T: DeserializeOwned>(&self, name: &'static str) -> Option<T> {
        serde_json::from_value(self.fields.get(name)?.clone()).ok()
    }
}

impl PartialEq for Span {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.fields, &other.fields) && Arc::ptr_eq(&self.exporter, &other.exporter)
    }
}

impl Default for Span {
    fn default() -> Self {
        Self::new(Arc::new(NullExporter), HashMap::new())
    }
}

pub struct Entered {
    previous: Option<Span>,
}

mod current_span {
    use std::cell::RefCell;

    use super::{Entered, Span};

    thread_local! {
        pub static CURRENT_SPAN: RefCell<Span> = RefCell::new(Span::default());
    }

    impl Drop for Entered {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                CURRENT_SPAN.with(|span| {
                    span.replace(previous.clone());
                });
            }
        }
    }

    impl Span {
        pub fn enter(&self) -> Entered {
            let previous = CURRENT_SPAN.with(|current| {
                if &*current.borrow() == self {
                    None
                } else {
                    Some(current.replace(self.clone()))
                }
            });
            Entered { previous }
        }

        pub fn in_scope<T>(&self, f: impl FnOnce() -> T) -> T {
            let _guard = self.enter();
            f()
        }

        pub fn current() -> Span {
            CURRENT_SPAN.with(|span| span.borrow().clone())
        }
    }
}

pin_project_lite::pin_project! {
    pub struct Instrumented<F: ?Sized> {
        span: Span,
        #[pin]
        inner: F,
    }
}

pub trait Instrument {
    fn instrument(self, span: Span) -> Instrumented<Self>;

    fn instrument_in_current(self) -> Instrumented<Self>;
}

impl<F: Future> Instrument for F {
    fn instrument(self, span: Span) -> Instrumented<Self> {
        Instrumented { span, inner: self }
    }

    fn instrument_in_current(self) -> Instrumented<Self> {
        self.instrument(crate::span!())
    }
}

impl<F: Future> Future for Instrumented<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        this.span.in_scope(|| this.inner.poll(cx))
    }
}

#[doc(hidden)]
pub mod macro_support {
    use serde::Serialize;

    use super::*;
    use crate::{BeSpecificEventData, EventBuilder};

    pub fn modify_event_builder_costom_fields(
        builder: &mut EventBuilder,
        f: impl FnOnce(&mut HashMap<String, Value>),
    ) {
        if builder.custom_fields.is_none() {
            builder.custom_fields = Some(HashMap::new());
        }
        let custom_fields = builder.custom_fields.as_mut().unwrap();
        f(custom_fields);
    }

    pub fn current_span_exporter() -> Arc<dyn ExportEvent> {
        current_span::CURRENT_SPAN.with(|span| span.borrow().exporter.clone())
    }

    pub fn current_span_fields() -> HashMap<&'static str, Value> {
        current_span::CURRENT_SPAN.with(|span| span.borrow().fields.as_ref().clone())
    }

    pub fn try_load_current_span<T: DeserializeOwned>(name: &'static str) -> Option<T> {
        current_span::CURRENT_SPAN.with(|span| {
            let span = span.borrow();
            Some(from_value::<T>(span.fields.get(name)?.clone()))
        })
    }

    pub fn build_and_emit_event<D: BeSpecificEventData>(
        build_data: impl FnOnce() -> D,
        build_event: impl FnOnce(D) -> Event,
    ) {
        if !filter::event(D::scheme()) {
            return;
        }
        let event = build_event(build_data());
        current_span::CURRENT_SPAN.with(|span| span.borrow().emit(event));
    }

    pub fn to_value<T: Serialize>(value: T) -> Value {
        serde_json::to_value(value).unwrap()
    }

    pub fn from_value<T: DeserializeOwned>(value: Value) -> T {
        serde_json::from_value(value).unwrap()
    }
}

#[macro_export]
macro_rules! span {
    () => {{
        $crate::telemetry::Span::current()
    }};
    (@current     $(, $($tt:tt)* )?) => {{
        let __current_exporter = $crate::telemetry::macro_support::current_span_exporter();
        $crate::span!(__current_exporter $(, $($tt)* )?)
    }};
    ($broker:expr $(, $($tt:tt)* )?) => {{
        #[allow(unused_mut)]
        let mut __current_fields = $crate::telemetry::macro_support::current_span_fields();
        $crate::span!(@field __current_fields $(, $($tt)* )?);
        $crate::telemetry::Span::new($broker, __current_fields)
    }};
    (@field $fields:expr, $name:ident               $(, $($tt:tt)* )?) => {
        $crate::span!( @field $fields, $name = $name $(, $($tt)* )? );
    };
    (@field $fields:expr, $name:ident = $value:expr $(, $($tt:tt)* )?) => {
        let __value = $crate::telemetry::macro_support::to_value($value);
        $fields.insert(stringify!($name), __value);
        $crate::span!( @field $fields $(, $($tt)* )? );
    };
    (@field $fields:expr $(,)? ) => {};
}

#[macro_export]
macro_rules! event {
    ($event_type:ty { $($evnet_field:tt)* } $(, $($tt:tt)* )?) => {{
        $crate::event!($crate::build!($event_type { $($evnet_field)* }) $(, $($tt)* )?);
    }};
    ($event_data:expr                       $(, $($tt:tt)* )?) => {{
        let __build_data = || $event_data;
        let __build_event = |__even_data| {
            let mut __event_builder = $crate::Event::builder();
            // as_millis_f64 is nightly only
            let __time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64()
                * 1000.0;
            __event_builder.time(__time);
            __event_builder.data(__even_data);
            $crate::event!(@load_known __event_builder, path: $crate::PathID);
            $crate::event!(@load_known __event_builder, protocol_types: $crate::ProtocolTypeList);
            $crate::event!(@load_known __event_builder, group_id: $crate::GroupID);
            $crate::event!(@field __event_builder $(, $($tt)* )?);

            __event_builder.build()
        };
        $crate::telemetry::macro_support::build_and_emit_event(__build_data, __build_event);
    }};
    (@load_known $event_builder:expr, $name:ident: $type:ty) => {
        if let Some(__value) = $crate::telemetry::macro_support::try_load_current_span::<$type>(stringify!($name)) {
            $event_builder.$name(__value);
        }
    };
    (@field $event_builder:expr, $name:ident               $(, $($tt:tt)* )?) => {
        $crate::event!( @field $event_builder, $name = $name $(, $($tt)* )? );
    };
    (@field $event_builder:expr, $name:ident = $value:expr $(, $($tt:tt)* )?) => {
        let __value = $crate::telemetry::macro_support::to_value($value);
        $crate::telemetry::macro_support::modify_event_builder_costom_fields(&mut $event_builder, |__custom_fields| {
            __custom_fields.insert(stringify!($name).to_owned(), __value);
        });
        $crate::event!( @field $event_builder $(, $($tt)* )? );
    };
    (@field $event_builder:expr $(,)? ) => {};
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use qbase::cid::ConnectionId;

    use super::*;
    use crate::{
        GroupID,
        quic::{ConnectionID, connectivity::ServerListening},
    };

    #[test]
    fn span_fields() {
        let exporter = Arc::new(NullExporter);
        let _span = span!(exporter.clone());
        let a = 0i32;
        let c = 123456789usize;
        span!(exporter.clone(), a, a, b = 12.3f32, c, d = "Hello world!").in_scope(|| {
            assert_eq!(Span::current().load::<i32>("a"), 0);
            assert_eq!(Span::current().load::<f32>("b"), 12.3);
            assert_eq!(Span::current().load::<usize>("c"), 123456789);
            assert_eq!(Span::current().load::<String>("d"), "Hello world!");
            let e = vec![1, 2, 3];
            span!(exporter.clone(), a = 1, b = 2, c = 3, e).in_scope(|| {
                assert_eq!(Span::current().load::<i32>("a"), 1);
                assert_eq!(Span::current().load::<i32>("b"), 2);
                assert_eq!(Span::current().load::<i32>("c"), 3);
                assert_eq!(Span::current().load::<String>("d"), "Hello world!");
                assert_eq!(Span::current().load::<Vec<i32>>("e"), vec![1, 2, 3]);
            });
        })
    }

    #[test]
    fn event() {
        struct TestBroker;

        impl ExportEvent for TestBroker {
            fn emit(&self, event: Event) {
                let str = serde_json::to_string_pretty(&event).unwrap();
                let event = serde_json::to_value(event).unwrap();
                println!("{str}");
                assert_eq!(event["name"], "quic:server_listening");
                let event_data_json = serde_json::json!({
                    "ip_v4": "127.0.0.1",
                    "port_v4": 8080,
                });
                assert_eq!(event["data"], event_data_json);
                assert_eq!(event["group_id"], String::from(group_id()));
                assert_eq!(event["use_strict_mode"], true);
            }
        }

        fn group_id() -> GroupID {
            GroupID::from(ConnectionID::from(ConnectionId::from_slice(&[
                0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
            ])))
        }

        span!(Arc::new(TestBroker), group_id = group_id()).in_scope(|| {
            event!(
                crate::build!(ServerListening {
                    ip_v4: "127.0.0.1".to_owned(),
                    port_v4: 8080u16,
                }),
                use_strict_mode = true
            );
        });
    }
}
