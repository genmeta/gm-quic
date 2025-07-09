#[macro_export]
#[cfg(feature = "telemetry")]
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
        $crate::telemetry::macro_support::new_span($broker, __current_fields)
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
#[cfg(not(feature = "telemetry"))]
macro_rules! span {
    ($($tt:tt)*) => {
        $crate::telemetry::Span::current()
    };
}

#[macro_export]
macro_rules! event {
    ($event_type:ty { $($evnet_field:tt)* } $(, $($tt:tt)* )?) => {{
        $crate::event!($crate::build!($event_type { $($evnet_field)* }) $(, $($tt)* )?);
    }};
    ($event_data:expr                       $(, $($tt:tt)* )?) => {{
        let __build_data = || $event_data;
        let __build_event = |__event_data| {
            let mut __event_builder = $crate::Event::builder();
            // as_millis_f64 is nightly only
            let __time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64()
                * 1000.0;
            __event_builder.time(__time);
            __event_builder.data(__event_data);
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
    (@field $event_builder:expr, $name:ident = Map           { $($build:tt)* } $(, $($tt:tt)* )?) => {
        let __value = $crate::telemetry::macro_support::to_value($crate::map!{ $($build)* });
        $crate::telemetry::macro_support::modify_event_builder_costom_fields(&mut $event_builder, |__custom_fields| {
            __custom_fields.insert(stringify!($name).to_owned(), __value);
        });
        $crate::event!( @field $event_builder $(, $($tt)* )? );
    };
    (@field $event_builder:expr, $name:ident = $struct:ident { $(build:tt)* } $(, $($tt:tt)* )?) => {
        let __value = $crate::telemetry::macro_support::to_value($crate::build!($struct { $(build)* }));
        $crate::telemetry::macro_support::modify_event_builder_costom_fields(&mut $event_builder, |__custom_fields| {
            __custom_fields.insert(stringify!($name).to_owned(), __value);
        });
        $crate::event!( @field $event_builder $(, $($tt)* )? );
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
