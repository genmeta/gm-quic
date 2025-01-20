use std::{net::SocketAddr, sync::Arc};

use gm_quic::QuicClient;
use rustls::{client::WebPkiServerVerifier, pki_types::CertificateDer};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cert_data = std::fs::read("/tmp/gm-quic/cert/cert.der").unwrap();
    let mut certs = rustls::RootCertStore::empty();
    certs.add(CertificateDer::from(cert_data))?;

    let verifier = WebPkiServerVerifier::builder(Arc::new(certs))
        .build()
        .unwrap();

    let v4 = "127.0.0.1:8080".parse().unwrap();
    let v6 = "[2001:db8::1]:8080".parse::<SocketAddr>().unwrap();
    let client = QuicClient::builder()
        .bind(&[v4, v6][..])?
        .reuse_connection()
        .prefer_versions([0x00000001u32])
        .with_webpki_verifier(verifier)
        .without_cert()
        .build();

    let _conn = client
        .connect("localhost", "127.0.0.1:5000".parse().unwrap())
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(100000)).await;
    Ok(())
}
