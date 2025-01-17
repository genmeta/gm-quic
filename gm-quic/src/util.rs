use std::path::Path;

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

pub struct Certificate(Vec<CertificateDer<'static>>);

impl From<Vec<CertificateDer<'static>>> for Certificate {
    fn from(cert: Vec<CertificateDer<'static>>) -> Self {
        Self(cert)
    }
}

pub trait ToCertificate {
    fn to_certificate(self) -> Vec<CertificateDer<'static>>;
}

impl ToCertificate for Certificate {
    fn to_certificate(self) -> Vec<CertificateDer<'static>> {
        self.0
    }
}

impl<P: AsRef<Path>> ToCertificate for P {
    fn to_certificate(self) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_file_iter(self.as_ref())
            .expect("failed to open cert file")
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to parse cert file")
    }
}

pub struct PrivateKey(PrivateKeyDer<'static>);

impl From<PrivateKeyDer<'static>> for PrivateKey {
    fn from(key: PrivateKeyDer<'static>) -> Self {
        Self(key)
    }
}

pub trait ToPrivateKey {
    fn to_private_key(self) -> PrivateKeyDer<'static>;
}

impl ToPrivateKey for PrivateKey {
    fn to_private_key(self) -> PrivateKeyDer<'static> {
        self.0
    }
}

impl<P: AsRef<Path>> ToPrivateKey for P {
    fn to_private_key(self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_file(self.as_ref()).expect("failed to parse private key file")
    }
}
