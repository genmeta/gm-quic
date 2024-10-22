use std::{
    io,
    ops::Deref,
    sync::{Arc, Mutex},
};

use qbase::{error::Error, param::Parameters};
use tokio::sync::Notify;

#[derive(Debug)]
enum SharedFutureState<T> {
    Demand(Arc<Notify>),
    Ready(T),
}

#[derive(Debug)]
struct SharedFuture<T>(Mutex<SharedFutureState<T>>);

impl<T> Default for SharedFuture<T> {
    fn default() -> Self {
        Self(SharedFutureState::Demand(Default::default()).into())
    }
}

impl<T: Clone> SharedFuture<T> {
    async fn get(&self) -> T {
        let notify;
        let notified = match self.0.lock().unwrap().deref() {
            SharedFutureState::Demand(ready) => {
                notify = ready.clone();
                notify.notified()
            }
            SharedFutureState::Ready(ready) => return ready.clone(),
        };

        notified.await;
        match self.0.lock().unwrap().deref() {
            SharedFutureState::Ready(ready) => ready.clone(),
            SharedFutureState::Demand(_) => unreachable!(),
        }
    }

    fn is_ready(&self) -> bool {
        matches!(self.0.lock().unwrap().deref(), SharedFutureState::Ready(..))
    }

    fn set_with(&self, with: impl FnOnce() -> T) {
        let mut state = self.0.lock().unwrap();
        match state.deref() {
            SharedFutureState::Demand(arc) => {
                arc.notify_waiters();
                *state = SharedFutureState::Ready(with());
            }
            SharedFutureState::Ready(..) => {}
        }
    }
}

/// A struct to asynchronously get the peer's transport parameters.
#[derive(Default, Debug, Clone)]
pub struct RemoteParameters(Arc<SharedFuture<Result<Arc<Parameters>, Error>>>);

impl RemoteParameters {
    /// Create a new [`RemoteParameters`] in demand state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Asynchronously get the transport parameters from the peer.
    ///
    /// If the parameters are not ready, the call will be blocked.
    ///
    /// If the connection is closed before the parameters are ready, an error will be returned.
    pub async fn read(&self) -> io::Result<Arc<Parameters>> {
        Ok(self.0.get().await?)
    }

    /// Check if the transport parameters are ready or the connection is closed.
    pub fn is_ready(&self) -> bool {
        self.0.is_ready()
    }

    /// Called when the peer's transport parameters are ready, only be used by [`ArcTlsSession`].
    ///
    /// [`ArcTlsSession`]: crate::tls::ArcTlsSession
    pub fn write(&self, params: Arc<Parameters>) {
        self.0.set_with(|| Ok(params));
    }

    /// Called when a connection error occurs.
    ///
    /// Once the connection is closed, the transport parameters from peer will never be ready. So
    /// this method will wake all blocked [`RemoteParameters::on_conn_error`] calls.
    pub fn on_conn_error(&self, error: &Error) {
        self.0.set_with(|| Err(error.clone()));
    }
}

/// A struct to store the local and remote transport parameters of a connection.
///
/// The local parameters are the parameters of the local endpoint, its invariant [`Parameters`].
///
/// The remote parameters are the parameters of the remote endpoint, its [`RemoteParameters`] the
/// is not ready when the structure is created. Other components can asynchronously get the remote
/// parameters by calling [`RemoteParameters::read`].
#[derive(Debug, Clone)]
pub struct ConnParameters {
    pub local: Arc<Parameters>,
    pub remote: RemoteParameters,
}

impl ConnParameters {
    /// Create a new [`ConnParameters`] with the local parameters and the remote parameters.
    pub fn new(local: Arc<Parameters>, remote: RemoteParameters) -> Self {
        Self { local, remote }
    }

    /// Called when a connection error occurs, read [`RemoteParameters::on_conn_error`] for more.
    pub fn on_conn_error(&self, error: &Error) {
        self.remote.on_conn_error(error);
    }
}
