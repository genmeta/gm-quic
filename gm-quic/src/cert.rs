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
        let data = std::fs::read(self).expect("failed to read certificate file");
        if let Ok(certs) = CertificateDer::pem_slice_iter(&data).collect::<Result<Vec<_>, _>>() {
            if !certs.is_empty() {
                return certs;
            }
        }

        vec![CertificateDer::from(data)]
    }
}

impl ToCertificate for &[u8] {
    fn to_certificate(self) -> Vec<CertificateDer<'static>> {
        if let Ok(certs) = CertificateDer::pem_slice_iter(self).collect::<Result<Vec<_>, _>>() {
            if !certs.is_empty() {
                return certs;
            }
        }

        vec![CertificateDer::from(self.to_vec())]
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
        let data = std::fs::read(self).expect("failed to read private key file");
        if let Ok(key) = PrivateKeyDer::from_pem_slice(&data) {
            return key;
        }

        PrivateKeyDer::try_from(data)
            .expect("failed to parse private key file as pem or der format")
    }
}

impl ToPrivateKey for &[u8] {
    fn to_private_key(self) -> PrivateKeyDer<'static> {
        if let Ok(key) = PrivateKeyDer::from_pem_slice(self) {
            return key;
        }

        PrivateKeyDer::try_from(self.to_vec())
            .expect("failed to parse private key file as pem or der format")
    }
}

impl<const N: usize> ToPrivateKey for &[u8; N] {
    fn to_private_key(self) -> PrivateKeyDer<'static> {
        <&[u8]>::to_private_key(self)
    }
}
