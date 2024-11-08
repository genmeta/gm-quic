use std::{io, path::Path};

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

pub fn parse_cert_files(
    cert_chain_file: impl AsRef<Path>,
    key_file: impl AsRef<Path>,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cast_pem_error = |e, path: &Path| match e {
        rustls::pki_types::pem::Error::Io(error) => error,
        pem_error => {
            let file_path = path.file_name().unwrap().to_string_lossy();
            let error = format!("faild to parse pem file `{file_path}`: `{pem_error}`");
            io::Error::new(io::ErrorKind::InvalidData, error)
        }
    };
    let cert_chain = CertificateDer::pem_file_iter(cert_chain_file.as_ref())
        .map_err(|e| cast_pem_error(e, cert_chain_file.as_ref()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| cast_pem_error(e, cert_chain_file.as_ref()))?;
    let key_der = PrivateKeyDer::from_pem_file(key_file.as_ref())
        .map_err(|e| cast_pem_error(e, key_file.as_ref()))?;
    Ok((cert_chain, key_der))
}
