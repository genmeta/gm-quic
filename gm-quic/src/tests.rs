mod echo_server {
    use crate as gm_quic;
    include!("../examples/echo_server.rs");
}

fn client_stream_unlimited_parameters() -> crate::ClientParameters {
    let mut params = crate::ClientParameters::default();

    params.set_initial_max_streams_bidi(100);
    params.set_initial_max_streams_uni(100);
    params.set_initial_max_data((1u32 << 20).into());
    params.set_initial_max_stream_data_uni((1u32 << 20).into());
    params.set_initial_max_stream_data_bidi_local((1u32 << 20).into());
    params.set_initial_max_stream_data_bidi_remote((1u32 << 20).into());

    params
}

use std::{io, sync::Arc};

use echo_server::server_stream_unlimited_parameters;
use rustls::RootCertStore;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};
use tracing::{debug, info, info_span, Instrument};

use crate::ToCertificate;

#[tokio::test]
async fn parallel_stream() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::TRACE)
        .with_ansi(false)
        .init();

    let server = crate::QuicServer::builder()
        .without_cert_verifier()
        .with_single_cert(
            include_bytes!("../examples/keychain/localhost/server.cert"),
            include_bytes!("../examples/keychain/localhost/server.key"),
        )
        .with_parameters(server_stream_unlimited_parameters())
        .listen("0.0.0.0:0")?;

    let server_addr = server.addresses().into_iter().next().unwrap();
    tokio::spawn(echo_server::launch(server));

    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(
        include_bytes!("../examples/keychain/localhost/ca.cert").to_certificate(),
    );

    let client = Arc::new(
        crate::QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .with_parameters(client_stream_unlimited_parameters())
            .build(),
    );

    const CONNECTIONS: usize = 1;
    const STREAMS: usize = 4;
    const DATA: &[u8] = include_bytes!("tests.rs");

    let mut connections = JoinSet::new();

    async fn for_eacho_connection(connection: Arc<crate::Connection>) -> io::Result<()> {
        let mut streams = JoinSet::new();
        for stream_idx in 0..STREAMS {
            streams.spawn({
                let connection = connection.clone();
                async move {
                    let (stream_id, (mut reader, mut writer)) =
                        connection.open_bi_stream().await?.unwrap();
                    debug!(%stream_id, "opened stream");

                    writer.write_all(DATA).await?;
                    writer.shutdown().await?;
                    debug!(%stream_id, "sender shutdowned, wait for shutdown");

                    let mut data = Vec::new();
                    reader.read_to_end(&mut data).await?;

                    info!("stream correctly echoed");

                    io::Result::Ok(())
                }
                .instrument(info_span!("stream", stream_idx))
            });
        }

        streams.join_all().await.into_iter().collect()
    }

    for conn_idx in 0..CONNECTIONS {
        connections.spawn({
            let client = client.clone();
            async move {
                let connection = client.connect("localhost", server_addr)?;
                for_eacho_connection(connection).await
            }
            .instrument(info_span!("connection", conn_idx))
        });
    }

    connections.join_all().await.into_iter().collect()
}
