use derive_more::From;
use qbase::{error::Error as QuicError, time::IdleTimedOut};
use qcongestion::TooManyPtos;
use qinterface::logical::BindUri;
use thiserror::Error;

use crate::path::validate::ValidateFailure;

#[derive(Debug, From, Error)]
pub enum CreatePathFailure {
    #[error("Network interface not found for bind URI: {0}")]
    NoInterface(BindUri),
    #[error("Connection is closed")]
    ConnectionClosed(QuicError),
}

#[derive(Debug, From, Error)]
pub enum PathDeactivated {
    #[error("Path validation failed")]
    Invalid(#[source] ValidateFailure),
    #[error(transparent)]
    Idle(IdleTimedOut),
    #[error("Lost path state")]
    Lost(#[source] TooManyPtos),
    #[error("Failed to send packets on path")]
    Io(#[source] std::io::Error),
    #[error("Manually removed by application")]
    App,
}
