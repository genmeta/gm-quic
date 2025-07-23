use derive_more::From;
use qbase::{error::Error as QuicError, net::addr::BindUri, time::IdleTimedOut};
use qcongestion::TooManyPtos;
use thiserror::Error;

use crate::path::validate::ValidateFailure;

#[derive(Debug, From, Error)]
pub enum CreatePathFailure {
    #[error("Network interface not found for bind URI: {0}")]
    NoInterface(BindUri),
    #[error("Connection is closed: {0}")]
    ConnectionClosed(QuicError),
}

#[derive(Debug, From, Error)]
pub enum PathDeactivated {
    #[error("Path validation failed: {0}")]
    Invalid(#[source] ValidateFailure),
    #[error(transparent)]
    Idle(IdleTimedOut),
    #[error("Lost path state: {0}")]
    Lost(#[source] TooManyPtos),
    #[error("Failed to send packets on path: {0}")]
    Io(#[source] std::io::Error),
    #[error("Manually removed by application")]
    App,
}
