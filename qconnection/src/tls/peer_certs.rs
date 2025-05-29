use std::{ops::Deref, sync::Arc};

use qbase::{error::Error, util::Future};
use rustls::pki_types::CertificateDer;

/// The certificate chain or the raw public key used by the peer to authenticate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCert {
    /// If the client auth is not required, the peer may not present any certificate.
    None,
    CertOrPublicKey(Vec<u8>),
}

#[derive(Default, Debug, Clone)]
pub struct ArcPeerCerts(Arc<Future<Result<Arc<PeerCert>, Error>>>);

impl ArcPeerCerts {
    pub fn assign(&self, certs: &[CertificateDer<'static>]) -> Result<Arc<PeerCert>, Error> {
        let previous = self
            .0
            .assign(Ok(Arc::new(PeerCert::CertOrPublicKey(certs[0].to_vec()))));
        debug_assert!(previous.is_none());
        self.0
            .try_get()
            .expect("PeerCerts has been ready")
            .deref()
            .clone()
    }

    pub fn no_certs(&self) {
        let previous = self.0.assign(Ok(Arc::new(PeerCert::None)));
        debug_assert!(previous.is_none())
    }

    pub(super) fn is_ready(&self) -> bool {
        self.0.try_get().is_some()
    }

    pub async fn get(&self) -> Result<Arc<PeerCert>, Error> {
        let r = self.0.get().await.deref().clone();
        r
    }

    pub fn on_conn_error(&self, error: &Error) {
        self.0.assign(Err(error.clone()));
    }
}
