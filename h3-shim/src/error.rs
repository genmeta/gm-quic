use std::{error::Error, sync::Arc};

use h3::quic::{ConnectionErrorIncoming, StreamErrorIncoming};
use qbase::frame::ResetStreamError;

pub fn convert_quic_error(e: qbase::error::Error) -> ConnectionErrorIncoming {
    match e {
        qbase::error::Error::Quic(quic_error) => {
            ConnectionErrorIncoming::Undefined(Arc::new(quic_error))
        }
        qbase::error::Error::App(app_error) => ConnectionErrorIncoming::ApplicationClose {
            error_code: app_error.error_code(),
        },
    }
}

pub fn convert_stream_io_error(e: std::io::Error) -> StreamErrorIncoming {
    if let Some(reset_stream_error) = e
        .source()
        .and_then(|e| e.downcast_ref::<ResetStreamError>())
    {
        return StreamErrorIncoming::StreamTerminated {
            error_code: reset_stream_error.error_code(),
        };
    }
    if let Some(quic_error) = e
        .source()
        .and_then(|e| e.downcast_ref::<qbase::error::Error>())
    {
        return StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: convert_quic_error(quic_error.clone()),
        };
    }
    StreamErrorIncoming::Unknown(e.into())
}
