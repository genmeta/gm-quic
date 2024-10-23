use std::{error, fmt, io, sync::Arc};

use qbase::frame::ResetStreamError;

pub mod conn;
pub use conn::QuicConnection;
pub mod ext;
pub use ext::{RecvDatagram, SendDatagram};
pub mod streams;
pub use streams::{BidiStream, RecvStream, SendStream};

#[derive(Clone)]
pub struct Error(Arc<io::Error>);

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for Error {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl error::Error for Error {
    #[inline]
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.0.source()
    }
}

impl h3::quic::Error for Error {
    #[inline]
    fn is_timeout(&self) -> bool {
        false
    }

    #[inline]
    fn err_code(&self) -> Option<u64> {
        error::Error::source(self)
            .and_then(|e| e.downcast_ref::<ResetStreamError>().map(|e| e.error_code()))
    }
}

impl From<io::Error> for Error {
    #[inline]
    fn from(value: io::Error) -> Self {
        Self(value.into())
    }
}

impl From<ResetStreamError> for Error {
    #[inline]
    fn from(value: ResetStreamError) -> Self {
        io::Error::new(io::ErrorKind::BrokenPipe, value).into()
    }
}
