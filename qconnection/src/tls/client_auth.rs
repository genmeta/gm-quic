use std::{
    ops::Deref,
    sync::Arc,
    task::{Context, Poll},
};

use qbase::{error::Error, param::ClientParameters, util::Future};

use crate::prelude::PeerCerts;

pub type ClientAuthers = Vec<Arc<dyn AuthClient>>;

pub trait AuthClient: Send + Sync {
    fn verify_server_name(&self, server_name: &str) -> bool;

    fn verify_client_params(&self, host: &str, clinet_params: &ClientParameters) -> bool;

    fn verify_client_certs(
        &self,
        host: &str,
        clinet_params: &ClientParameters,
        clinet_certs: &PeerCerts,
    ) -> bool;
}

/// A gate that controls server transmission permissions during parameter verification.
///
/// `SendGate` is used by the server to restrict data transmission until transport
/// parameter validation and server name verification are completed. It provides operations to:
/// - `request_permit()`: Request permission to send (public method)
/// - `grant_permit()`: Grant permission to send (internal method, pub(super) visibility)
///
/// This mechanism ensures that the server sends no data until it has properly validated
/// the client's transport parameters and verified the requested server name (SNI),
/// enhancing security by preventing premature data transmission before proper validation.
#[derive(Default, Debug, Clone)]
pub struct ArcSendGate(Arc<Future<Result<(), Error>>>);

impl ArcSendGate {
    /// Create a new `SendGate` in the restricted state.
    ///
    /// Transmission will be blocked until client parameters and server
    /// verification are completed, or when silent rejection is not enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new `SendGate` in the unrestricted state.
    ///
    /// Transmission is immediately permitted, used when silent rejection
    /// is disabled or verification has already been completed.
    pub fn unrestricted() -> Self {
        Self(Future::with(Ok(())).into())
    }

    /// Request permission to send data.
    ///
    /// This method will block until client parameters and server verification
    /// are completed, or connection error occured.
    ///
    /// This method will not block when silent rejection is not enabled
    pub async fn request_permit(&self) -> Result<(), Error> {
        self.0.get().await.deref().clone()
    }

    /// Poll for permission to send data.
    ///
    /// `poll` version of [`request_permit`].
    /// 
    /// [`request_permit`]: Self::request_permit
    pub fn poll_request_permit(&self, cx: &mut Context) -> Poll<Result<(), Error>> {
        self.0.poll_get(cx).map(|r| r.deref().clone())
    }

    /// Check if transmission is currently permitted.
    pub fn is_permitted(&self) -> bool {
        self.0.try_get().is_some()
    }

    /// Grant permission for transmission.
    ///
    /// Called after client parameters and server verification are completed
    /// successfully. Unblocks all pending transmission requests.
    pub fn grant_permit(&self) {
        self.0.assign(Ok(()));
    }

    /// Unblock send task when an connection error occurs.
    ///
    /// Send task will be woken up, but still no data will be sent.
    pub fn on_conn_error(&self, error: &Error) {
        self.0.assign(Err(error.clone()));
    }
}
