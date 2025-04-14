use super::*;

fn launch_echo_server(
    parameters: ServerParameters,
) -> Result<(Arc<QuicServer>, impl Future<Output: Send>), Error> {
    let server = QuicServer::builder()
        .without_client_cert_verifier()
        .with_single_cert(SERVER_CERT, SERVER_KEY)
        .with_parameters(parameters)
        .with_qlog(QLOGGER.clone())
        .listen("127.0.0.1:0".parse::<SocketAddr>()?)?;
    Ok((server.clone(), serve_echo(server)))
}

#[test]
fn handshake() -> Result<(), Error> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", server_addr)?;
        connection.handshaked().await;
        connection.close("no error".into(), 0);
        Ok(())
    };
    run_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn single_stream() -> Result<(), Error> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", server_addr)?;
        send_and_verify_echo(&connection, include_bytes!("echo.rs")).await?;

        Ok(())
    };
    run_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn empty_stream() -> Result<(), Error> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", server_addr)?;
        send_and_verify_echo(&connection, b"").await?;

        Ok(())
    };
    run_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn shutdown() -> Result<(), Error> {
    async fn serve_only_one_stream(server: Arc<QuicServer>) -> io::Result<()> {
        loop {
            let (connection, pathway) = server.accept().await?;
            tracing::info!(source = ?pathway.remote(), "accepted new connection");
            tokio::spawn(async move {
                let (_sid, (reader, writer)) = connection.accept_bi_stream().await?.unwrap();
                echo_stream(reader, writer).await?;
                connection.close("no error".into(), 0);
                Result::<(), Error>::Ok(())
            });
        }
    }

    let launch_server = || {
        let server = QuicServer::builder()
            .without_client_cert_verifier()
            .with_single_cert(SERVER_CERT, SERVER_KEY)
            .with_parameters(server_parameters())
            .with_qlog(QLOGGER.clone())
            .listen("127.0.0.1:0".parse::<SocketAddr>()?)?;
        Ok((server.clone(), serve_only_one_stream(server)))
    };
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());
        let connection = client.connect("localhost", server_addr)?;
        connection.handshaked().await; // 可有可无

        assert!(
            send_and_verify_echo(&connection, b"").await.is_err()
                || send_and_verify_echo(&connection, b"").await.is_err()
        );

        Result::Ok(())
    };
    run_serially(launch_server, launch_client)
}


#[test]
fn parallel_stream() -> Result<(), Error> {
    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());

        let mut streams = JoinSet::new();

        for conn_idx in 0..PARALLEL_ECHO_CONNS {
            let connection = client.connect("localhost", server_addr)?;
            for stream_idx in 0..PARALLEL_ECHO_STREAMS {
                let connection = connection.clone();
                streams.spawn(
                    async move {
                        send_and_verify_echo(&connection, include_bytes!("echo.rs")).await
                    }
                    .instrument(tracing::info_span!("stream", conn_idx, stream_idx)),
                );
            }
        }

        streams
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), Error>>()?;

        Ok(())
    };
    run_serially(|| launch_echo_server(server_parameters()), launch_client)
}

#[test]
fn limited_streams() -> Result<(), Error> {
    fn client_parameters() -> ClientParameters {
        let mut params = ClientParameters::default();

        params.set_initial_max_streams_bidi(2u32);
        params.set_initial_max_streams_uni(0u32);
        params.set_initial_max_data(1u32 << 10);
        params.set_initial_max_stream_data_uni(1u32 << 10);
        params.set_initial_max_stream_data_bidi_local(1u32 << 10);
        params.set_initial_max_stream_data_bidi_remote(1u32 << 10);

        params
    }

    fn server_parameters() -> ServerParameters {
        let mut params = ServerParameters::default();

        params.set_initial_max_streams_bidi(2u32);
        params.set_initial_max_streams_uni(0u32);
        params.set_initial_max_data(1u32 << 10);
        params.set_initial_max_stream_data_uni(1u32 << 10);
        params.set_initial_max_stream_data_bidi_local(1u32 << 10);
        params.set_initial_max_stream_data_bidi_remote(1u32 << 10);

        params
    }

    let launch_client = |server_addr| async move {
        let client = launch_test_client(client_parameters());

        let mut streams = JoinSet::new();

        for conn_idx in 0..PARALLEL_ECHO_CONNS / 2 {
            let connection = client.connect("localhost", server_addr)?;
            for stream_idx in 0..PARALLEL_ECHO_STREAMS / 2 {
                let connection = connection.clone();
                streams.spawn(
                    async move { send_and_verify_echo(&connection, include_bytes!("echo.rs")).await }
                        .instrument(tracing::info_span!("stream", conn_idx, stream_idx)),
                );
            }
        }

        streams
            .join_all()
            .await
            .into_iter()
            .collect::<Result<(), Error>>()?;

        Ok(())
    };
    run_serially(|| launch_echo_server(server_parameters()), launch_client)
}
