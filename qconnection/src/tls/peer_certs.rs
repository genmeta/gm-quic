use std::{ops::Deref, sync::Arc};

use qbase::{error::Error, util::Future};
use rcgen::{CertificateParams, SubjectPublicKeyInfo};
use rustls::pki_types::CertificateDer;

/// The certificate chain or the raw public key used by the peer to authenticate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCerts {
    /// If the client auth is not required, the peer may not present any certificate.
    None,
    RawPublicKey(SubjectPublicKeyInfo),
    /// The order of the certificate chain is as it appears in the TLS protocol:
    /// the first certificate relates to the peer, the second certifies the first, the third certifies the second, and so on.
    CertChain(Vec<CertificateParams>),
}

#[derive(Default, Debug, Clone)]
pub struct ArcPeerCerts(Arc<Future<Result<Arc<PeerCerts>, Error>>>);

impl TryFrom<&[CertificateDer<'static>]> for PeerCerts {
    type Error = rcgen::Error;

    fn try_from(certs: &[CertificateDer<'static>]) -> Result<Self, Self::Error> {
        debug_assert!(!certs.is_empty());
        if certs.len() == 1 {
            if let Ok(public_key_info) = SubjectPublicKeyInfo::from_der(&certs[0]) {
                return Ok(Self::RawPublicKey(public_key_info));
            }
        }

        certs
            .iter()
            .try_fold(vec![], |mut acc, cert| {
                acc.push(CertificateParams::from_ca_cert_der(cert)?);
                Ok(acc)
            })
            .map(Self::CertChain)
    }
}

impl ArcPeerCerts {
    pub fn assign(&self, certs: &[CertificateDer<'static>]) {
        let previous = self.0.assign(Ok(Arc::new(
            PeerCerts::try_from(certs).expect("Failde to parse peer certificates"),
        )));
        debug_assert!(previous.is_none())
    }

    pub fn no_certs(&self) {
        let previous = self.0.assign(Ok(Arc::new(PeerCerts::None)));
        debug_assert!(previous.is_none())
    }

    pub(super) fn is_ready(&self) -> bool {
        self.0.try_get().is_some()
    }

    pub async fn get(&self) -> Result<Arc<PeerCerts>, Error> {
        let r = self.0.get().await.deref().clone();
        r
    }

    pub fn on_conn_error(&self, error: &Error) {
        self.0.assign(Err(error.clone()));
    }
}
