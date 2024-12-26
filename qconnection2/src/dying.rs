pub mod closed;
pub mod closing;
pub mod draining;

pub enum DyingState {
    Closing(closing::Connection),
    Draining(draining::Connection),
    Closed(closed::Connection),
}

impl From<closing::Connection> for DyingState {
    fn from(v: closing::Connection) -> Self {
        Self::Closing(v)
    }
}

impl From<draining::Connection> for DyingState {
    fn from(v: draining::Connection) -> Self {
        Self::Draining(v)
    }
}

impl From<closed::Connection> for DyingState {
    fn from(v: closed::Connection) -> Self {
        Self::Closed(v)
    }
}

pub struct DyingConnection {
    pub(crate) state: DyingState,
    pub(crate) error: qbase::error::Error,
}
