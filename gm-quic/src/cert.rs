use std::path::Path;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

pub trait ToCertificate {
    fn to_certificate(self) -> Vec<CertificateDer<'static>>;
}

impl ToCertificate for Vec<CertificateDer<'static>> {
    fn to_certificate(self) -> Vec<CertificateDer<'static>> {
        self
    }
}

impl ToCertificate for &Path {
    fn to_certificate(self) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_file_iter(self)
            .expect("failed to open cert file")
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to parse cert file")
    }
}

impl ToCertificate for &[u8] {
    fn to_certificate(self) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(self)
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to parse cert file")
    }
}

impl<const N: usize> ToCertificate for &[u8; N] {
    fn to_certificate(self) -> Vec<CertificateDer<'static>> {
        <&[u8]>::to_certificate(self)
    }
}

pub trait ToPrivateKey {
    fn to_private_key(self) -> PrivateKeyDer<'static>;
}

impl ToPrivateKey for PrivateKeyDer<'static> {
    fn to_private_key(self) -> PrivateKeyDer<'static> {
        self
    }
}

impl ToPrivateKey for &Path {
    fn to_private_key(self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_file(self).expect("failed to parse private key file")
    }
}

impl ToPrivateKey for &[u8] {
    fn to_private_key(self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_slice(self).expect("failed to parse private key file")
    }
}

impl<const N: usize> ToPrivateKey for &[u8; N] {
    fn to_private_key(self) -> PrivateKeyDer<'static> {
        <&[u8]>::to_private_key(self)
    }
}
