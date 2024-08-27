use std::{io::Write, os::unix::net::SocketAddr, path::Path};

use quic::QuicServer;
use rcgen::CertifiedKey;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let cert_path = "/tmp/gm-quic/cert/cert.der";
    let key_path = "/tmp/gm-quic/cert/key.der";

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    generate_certificate(&cert_path, &key_path)?;

    let server_addr = ["127.0.0.1:12345".parse().unwrap()];
    let builder = QuicServer::bind(server_addr, true);

    let mut server = builder
        .without_cert_verifier()
        .with_single_cert(cert_path, key_path)
        .listen();

    let (connection, addr) = server.accept().await?;
    println!("Accepted connection from: {}, conn {:?}", addr, connection);
    Ok(())
}

fn generate_certificate(cert_path: &str, key_path: &str) -> Result<(), std::io::Error> {
    let cert_path = Path::new(cert_path);
    if cert_path.exists() {
        return Ok(());
    }
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert);

    let mut cert_file = std::fs::File::create(cert_path)?;
    let mut private_key_file = std::fs::File::create(key_path)?;

    let priv_key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    cert_file.write_all(&cert_der)?;
    private_key_file.write_all(&priv_key.secret_pkcs8_der())?;
    Ok(())
}
