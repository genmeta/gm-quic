use std::sync::Arc;

use quic::QuicClient;
use rustls::{client::WebPkiServerVerifier, pki_types::CertificateDer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cert_data = std::fs::read("/tmp/gm-quic/cert/server_cert.der").unwrap();
    let mut certs = rustls::RootCertStore::empty();
    certs.add(CertificateDer::from(cert_data))?;

    let verifier = WebPkiServerVerifier::builder(Arc::new(certs))
        .build()
        .unwrap();

    let client = QuicClient::bind([
        "[2001:db8::1]:8080".parse().unwrap(),
        "127.0.0.1:8080".parse().unwrap(),
    ])
    .reuse_connection()
    .enable_happy_eyeballs()
    .prefer_versions([0x00000001u32])
    .with_webpki_verifier(verifier)
    .without_cert()
    .build();

    let _conn = client
        .connect("localhost".to_string(), "127.0.0.1:5000".parse().unwrap())
        .unwrap();
    Ok(())
}
