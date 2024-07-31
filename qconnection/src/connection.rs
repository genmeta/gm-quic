use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use qbase::{config::TransportParameters, error::Error};
use qrecovery::streams::DataStreams;

pub mod closing;
pub mod draining;
pub mod raw;

#[derive(Debug)]
enum ConnState {
    // Raw(raw::RawConnection),
    // Closing(closing::ClosingConnection),
    Draining(draining::DrainingConnection),
}

#[derive(Debug, Clone)]
pub struct ArcConnection(Arc<Mutex<ConnState>>);

impl ArcConnection {
    pub fn new_client(
        _server_name: String,
        _address: SocketAddr,
        _token: Option<Vec<u8>>,
        _parameters: TransportParameters,
    ) -> Self {
        todo!("create a new client connection");
    }

    /// TODO: 参数不全，其实是QuicServer::accept的返回值
    pub fn new_server(_parameters: TransportParameters) -> Self {
        todo!("create a new server connection");
    }

    /// Get the streams of the connection, return error if the connection is in closing state or
    /// draining state. Even if the connection will enter closing state in future, the returned
    /// data streams are still available. It doesn't matter, because the returned DataStreams will
    /// be synced into Error state, and do anything about this DataStreams will return an Error.
    pub fn streams(&self) -> Result<DataStreams, Error> {
        todo!("get the streams of the connection, return error if the connection is in closing state or draining state")
    }

    /// Enter closing state from raw state. There might already be an error within the connection,
    /// in which case the error parameter is not useful.
    /// However, if the app actively closes the connection, the error parameter represents the
    /// reason for the app's active closure.
    /// The app then releases a reference count of the connection, allowing the connection to enter
    /// a self-destruct process.
    pub fn close(&self, _error: Error) {
        // TODO: 状态切换 RawConnection -> ClosingConnection
        // TODO: 监听 ClosingConnection.error.did_error_occur().await , 返回 (_, false) 则进入 Draining
        todo!("enter closing state from raw state");
    }

    /// Enter draining state from raw state or closing state.
    /// Can only be called internally, and the app should not care this method.
    pub(crate) fn drain(&self, _pto: Duration) {
        todo!("enter draining state from raw state or closing state");
    }

    /// Dismiss the connection, remove it from the global router.
    /// Can only be called internally, and the app should not care this method.
    pub(crate) fn die(&self) {
        todo!("remove the connection from the global router");
    }
}

#[cfg(test)]
mod tests {}
