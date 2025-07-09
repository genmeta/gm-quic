/// A macro to crate a qlog event struct from a set of fields.
#[macro_export]
macro_rules! build {
    ($struct:ty { $($tt:tt)* }) => {{
        let mut __builder = <$struct>::builder();
        $crate::build!(@field __builder, $($tt)*);
        __builder.build()
    }};
    (@field $builder:expr, $field:ident $(, $($remain:tt)* )? ) => {
        $builder.$field($field);
        $crate::build!(@field $builder $(, $($remain)* )? );
    };
    (@field $builder:expr, $field:ident: Map        { $($tt:tt)* } $(, $($remain:tt)* )? ) => {
        $builder.$field($crate::map!{ $($tt)* });
        $crate::build!(@field $builder $(, $($remain)* )? );
    };
    (@field $builder:expr, $field:ident: $struct:ty { $($tt:tt)* } $(, $($remain:tt)* )? ) => {
        $builder.$field($crate::build!($struct { $($tt)* }));
        $crate::build!(@field $builder $(, $($remain)* )? );
    };
    (@field $builder:expr, $field:ident: $value:expr $(, $($remain:tt)* )? ) => {
        $builder.$field($value);
        $crate::build!(@field $builder $(, $($remain)* )? );
    };
    (@field $builder:expr, ? $field:ident $(, $($remain:tt)* )? ) => {
        if let Some(__value) = $field {
            $builder.$field(__value);
        }
        $crate::build!(@field $builder $(, $($remain)* )? );
    };
    (@field $builder:expr, ? $field:ident: $value:expr $(, $($remain:tt)* )? ) => {
        if let Some(__value) = $value {
            $builder.$field(__value);
        }
        $crate::build!(@field $builder $(, $($remain)* )? );
    };
    (@field $builder:expr $(,)?) => {};
}

/// A macro to create a `HashMap<String, Value>` from a set of fields.
/// ``` rust, ignore
/// qevent::map! {
///     field1: value,
///     field2,
///     field3: Map {
///        subfield1: value,
///     },
///     event: loglevel::Error {
///          message: "An error occurred",
///     }
/// }
/// ```
#[macro_export]
macro_rules! map {
    {$($tt:tt)*}=>{ {
        let mut map = ::std::collections::HashMap::<String, $crate::macro_support::Value>::new();
        $crate::map_internal!(map, $($tt)*);
        map
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! map_internal {
    ($map:expr, $field:ident $(, $($remain:tt)* )?) => {
        $map.insert(stringify!($field).to_owned(), $field.into());
        $crate::map_internal!($map $(, $($remain)* )?)
    };
    ($map:expr, $field:ident: Map         {$($tt:tt)*} $(, $($remain:tt)* )?) => {
        $map.insert(stringify!($field).to_owned(), $crate::map!{ $($tt)* });
        $crate::map_internal!($map $(, $($remain)* )?)
    };
    ($map:expr, $field:ident: $struct:ty  {$($tt:tt)*} $(, $($remain:tt)* )?) => {
        $map.insert(stringify!($field).to_owned(), $crate::build!($struct { $($tt)* }).into());
        $crate::map_internal!($map $(, $($remain)* )?)
    };
    ($map:expr, $field:ident: $value:expr $(, $($remain:tt)* )?) => {
        $map.insert(stringify!($field).to_owned(), $value.into());
        $crate::map_internal!($map $(, $($remain)* )?)
    };
    ($map:expr $(,)?) => {};
}
