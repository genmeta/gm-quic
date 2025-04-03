use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use gm_quic::{QuicClient, ToCertificate};
use http::Uri;
use tokio::{
    fs,
    io::{self, AsyncWriteExt},
    task::JoinSet,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt().init();
    if let Err(error) = run().await {
        tracing::error!(?error, "client error");
        std::process::exit(1);
    };
}

pub type Error = Box<dyn std::error::Error + Send + Sync>;

async fn run() -> Result<(), Error> {
    let testcase = std::env::var("TESTCASE").expect("TESTCASE env var not set");
    let requests = std::env::var("REQUESTS").expect("REQUESTS env var not set");
    let requests = requests
        .split_whitespace()
        .map(|s| s.parse::<Uri>().map_err(Error::from))
        .collect::<Result<Vec<_>, Error>>()?;

    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(fs::read("/cert/ca.pem").await?.to_certificate());
    // roots.add_parsable_certificates(
    //     include_bytes!("../../benchmark/certs/root_cert.pem").to_certificate(),
    // );

    let client = Arc::new(
        gm_quic::QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .with_alpns(["hq-29"])
            .build(),
    );

    match testcase.as_str() {
        "handshake" | "transfer" => download_http09(client, requests).await,
        "http3" => download_http3(client, requests).await,
        _ => std::process::exit(-127),
    }
}

pub async fn lookup_uri(uri: &Uri) -> Result<(&str, SocketAddr), Error> {
    let auth = uri.authority().unwrap();
    let mut addrs = tokio::net::lookup_host((auth.host(), auth.port_u16().unwrap_or(443)))
        .await?
        .collect::<Vec<_>>();
    addrs.sort_by_key(|a| a.is_ipv4());
    let addr = *addrs.first().ok_or("dns found no ipv6 addresses")?;
    tracing::info!("DNS lookup for {:?}: {:?}", auth.host(), addr);
    Ok((auth.host(), addr))
}

async fn download_http09(client: Arc<QuicClient>, uris: Vec<Uri>) -> Result<(), Error> {
    async fn download_http09(client: Arc<QuicClient>, uri: Uri) -> Result<(), Error> {
        let (server_name, server_addr) = lookup_uri(&uri).await?;
        let connection = client.connect(server_name, server_addr)?;
        let (_sid, (mut response, mut request)) = connection
            .open_bi_stream()
            .await?
            .expect("very very hard to exhaust the available stream ids");
        request
            .write_all(format!("GET /{}", uri.path()).as_bytes())
            .await?;
        request.shutdown().await?;

        let storage =
            PathBuf::from_iter([PathBuf::from("/downloads").as_path(), uri.path().as_ref()]);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(storage)
            .await?;
        io::copy(&mut response, &mut file).await?;
        Ok(())
    }

    let mut requests = JoinSet::new();
    for uri in uris {
        requests.spawn(download_http09(client.clone(), uri));
    }
    requests.join_all().await.into_iter().collect()
}

async fn download_http3(client: Arc<QuicClient>, uris: Vec<Uri>) -> Result<(), Error> {
    async fn download_http3(client: Arc<QuicClient>, uri: Uri) -> Result<(), Error> {
        let (server_name, server_addr) = lookup_uri(&uri).await?;
        let connection = client.connect(server_name, server_addr)?;
        let (mut connection, mut send_request) =
            h3::client::new(h3_shim::QuicConnection::new(connection).await).await?;
        tokio::spawn(async move { connection.wait_idle().await });

        let mut request_stream = send_request
            .send_request(http::Request::get(uri.clone()).body(())?)
            .await?;

        request_stream.recv_response().await?;
        let storage =
            PathBuf::from_iter([PathBuf::from("/downloads").as_path(), uri.path().as_ref()]);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(storage)
            .await?;
        while let Some(mut data) = request_stream.recv_data().await? {
            file.write_all_buf(&mut data).await?;
        }

        Ok(())
    }

    let mut requests = JoinSet::new();
    for uri in uris {
        requests.spawn(download_http3(client.clone(), uri));
    }
    requests.join_all().await.into_iter().collect()
}
