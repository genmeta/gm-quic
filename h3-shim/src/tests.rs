use std::path::PathBuf;

mod client_example {
    use crate as h3_shim;
    include!("../examples/h3-client.rs");
}

mod server_example {
    use crate as h3_shim;
    include!("../examples/h3-server.rs");
}

#[tokio::test]
async fn h3_test() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stdout)
        .init();
    // CryptoProvider ring is installed automatically.

    let client_opt = client_example::Opt {
        ca: PathBuf::from("examples/ca.cert"),
        key_log_file: true,
        bind: vec!["127.0.0.1:0".parse().unwrap(), "[::1]:0".parse().unwrap()],
        uri: "https://localhost:4433/Cargo.toml".to_string(),
    };

    let server_opt = server_example::Opt {
        root: PathBuf::from("./"),
        listen: vec![
            "127.0.0.1:4433".parse().unwrap(),
            "[::1]:4433".parse().unwrap(),
        ],
        certs: server_example::Certs {
            cert: PathBuf::from("examples/server.cert"),
            key: PathBuf::from("examples/server.key"),
        },
    };

    let client = async move {
        client_example::run(client_opt)
            .await
            .expect("client failed");
    };

    let server = async move {
        // give it a litte time to enter draining state...
        let test_time = std::time::Duration::from_secs(2);
        let run = server_example::run(server_opt);
        match tokio::time::timeout(test_time, run).await {
            Ok(result) => result.expect("server failed"),
            Err(_finish) => { /* ok */ }
        }
    };
    tokio::join!(server, client);
}
