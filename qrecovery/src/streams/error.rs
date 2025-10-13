use std::io;

use qbase::{error::Error, frame::ResetStreamError};
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    #[error(transparent)]
    Connection(#[from] Error),
    #[error(transparent)]
    Reset(#[from] ResetStreamError),
    #[error("EOS has been sent")]
    EosSent,
}

impl From<StreamError> for io::Error {
    fn from(value: StreamError) -> Self {
        match value {
            error @ (StreamError::Connection(..) | StreamError::Reset(..)) => {
                io::Error::new(io::ErrorKind::BrokenPipe, error)
            }
            error @ StreamError::EosSent => io::Error::new(io::ErrorKind::Unsupported, error),
        }
    }
}
