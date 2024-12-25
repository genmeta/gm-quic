pub mod closed;
pub mod closing;
pub mod draining;

pub enum DyingState {
    Closing(closing::Connection),
    Draining(draining::Connection),
    Closed,
}

pub struct DyingConnection {
    pub(crate) state: DyingState,
    pub(crate) error: qbase::error::Error,
}
