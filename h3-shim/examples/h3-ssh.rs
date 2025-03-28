use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use futures::future;
use gm_quic::ToCertificate;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{Instrument, info, info_span, trace};

static ALPN: &[u8] = b"h3";

#[derive(Parser, Debug)]
#[structopt(name = "server")]
pub struct Options {
    #[structopt(
        long,
        short,
        default_value = "h3-shim/examples/ca.cert",
        help = "Certificate of CA who issues the server certificate"
    )]
    pub ca: PathBuf,

    #[structopt(long, short = 'b', default_value = "[::]:0")]
    pub bind: Vec<SocketAddr>,

    #[structopt(default_value = "https://localhost:4433/Cargo.lock")]
    pub uri: String,
}

#[cfg_attr(test, allow(unused))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn core::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stdout)
        .init();
    // console_subscriber::init();

    run(Options::parse()).await
}

pub async fn run(options: Options) -> Result<(), Box<dyn core::error::Error + Send + Sync>> {
    // DNS lookup

    let uri = options.uri.parse::<http::Uri>()?;
    if uri.scheme() != Some(&http::uri::Scheme::HTTPS) {
        return Err("uri scheme must be 'https'")?;
    }

    let auth = uri.authority().ok_or("uri must have a host")?.clone();
    let port = auth.port_u16().unwrap_or(443);
    let addr = tokio::net::lookup_host((auth.host(), port))
        .await?
        .next()
        .ok_or("dns found no addresses")?;
    info!("resolved {:?} to address: {:?}", uri, addr);

    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(options.ca.to_certificate());

    trace!(bind = ?options.bind, "QuicClient");
    let quic_client = ::gm_quic::QuicClient::builder()
        .with_root_certificates(roots)
        .without_cert()
        .with_alpns([ALPN])
        .with_parameters(client_parameters())
        .bind(&options.bind[..])?
        .build();
    info!(%addr, "connect to server");
    let conn = quic_client.connect(auth.host(), addr)?;

    // create h3 client

    let gm_quic_conn = h3_shim::QuicConnection::new(conn).await;
    let (mut conn, mut h3_client) = h3::client::new(gm_quic_conn).await?;
    let driver = async move {
        future::poll_fn(|cx| conn.poll_close(cx)).await?;
        // tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok::<_, Box<dyn std::error::Error + 'static + Send + Sync>>(())
    };

    // In the following block, we want to take ownership of `send_request`:
    // the connection will be closed only when all `SendRequest`s instances
    // are dropped.
    //
    //             So we "move" it.
    //                  vvvv
    let request = async move {
        info!(%uri, "request");

        let request = http::Request::builder().method("PUT").uri(uri).body(())?;

        // sending request results in a bidirectional stream,
        // which is also used for receiving response
        let mut stream = h3_client.send_request(request).await?;
        let response = stream.recv_response().await?;
        info!(?response, "received");

        let (mut sender, mut receiver) = stream.split();
        // read from stdin and write to the stream
        let send_task = tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = vec![0; 1024];
            loop {
                match stdin.read(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        sender.send_data(buf[..n].to_vec().into()).await?;
                    }
                    Err(e) => {
                        // shutdown on the sending side, no more data for the GET request
                        _ = sender
                            .finish()
                            .await
                            .inspect_err(|e| tracing::error!("failed to finish stream: {}", e));
                        return Err(e.into());
                    }
                }
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let recv_task = tokio::spawn(async move {
            let mut stdout = tokio::io::stdout();
            while let Some(mut chunk) = receiver.recv_data().await? {
                stdout.write_all_buf(&mut chunk).await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        // 等待两个任务完成
        let (send_result, recv_result) = tokio::join!(send_task, recv_task);
        send_result??;
        recv_result??;

        Ok::<_, Box<dyn std::error::Error + 'static + Send + Sync>>(())
    }
    .instrument(info_span!("ssh"));

    let derive = tokio::spawn(driver);
    let request = tokio::spawn(request);

    derive.await??;
    request.await??;

    Ok(())
}

fn client_parameters() -> gm_quic::ClientParameters {
    let mut params = gm_quic::ClientParameters::default();

    params.set_initial_max_streams_bidi(100u32);
    params.set_initial_max_streams_uni(100u32);
    params.set_initial_max_data(1u32 << 20);
    params.set_initial_max_stream_data_uni(1u32 << 20);
    params.set_initial_max_stream_data_bidi_local(1u32 << 20);
    params.set_initial_max_stream_data_bidi_remote(1u32 << 20);

    params
}
