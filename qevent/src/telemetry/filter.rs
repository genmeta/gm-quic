#[inline]
#[cfg(feature = "telemetry")]
pub fn event(scheme: &'static str) -> bool {
    super::current_span::CURRENT_SPAN.with(|span| span.borrow().filter_event(scheme))
}

#[inline]
#[cfg(not(feature = "telemetry"))]
pub fn event(_scheme: &'static str) -> bool {
    false
}

#[inline]
#[cfg(all(feature = "telemetry", feature = "raw_data"))]
pub fn raw_data() -> bool {
    super::current_span::CURRENT_SPAN.with(|span| span.borrow().filter_raw_data())
}

#[inline]
#[cfg(not(all(feature = "telemetry", feature = "raw_data")))]
pub fn raw_data() -> bool {
    false
}
