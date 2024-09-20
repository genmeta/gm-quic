use std::{
    io,
    ops::Deref,
    sync::{Arc, Mutex},
};

use qbase::{config::Parameters, error::Error};
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

#[derive(Default, Debug, Clone)]
pub struct RemoteParameters(Arc<SharedFuture<Result<Arc<Parameters>, Error>>>);

impl RemoteParameters {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn read(&self) -> io::Result<Arc<Parameters>> {
        Ok(self.0.get().await?)
    }

    pub fn write(&self, params: Arc<Parameters>) {
        self.0.set_with(|| Ok(params));
    }

    pub fn on_conn_error(&self, error: &Error) {
        self.0.set_with(|| Err(error.clone()));
    }
}

#[derive(Debug, Clone)]
pub struct ConnParameters {
    pub local: Arc<Parameters>,
    pub remote: RemoteParameters,
}

impl ConnParameters {
    pub fn new(local: Arc<Parameters>, remote: RemoteParameters) -> Self {
        Self { local, remote }
    }

    pub fn on_conn_error(&self, error: &Error) {
        self.remote.on_conn_error(error);
    }
}
