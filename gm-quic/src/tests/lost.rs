use std::sync::atomic::{AtomicBool, Ordering};

use rand::Rng;

use super::*;

struct JitterInterface<const JITTER: u8 = 0, const DROP_FIRST: bool = false> {
    usc: UdpSocketController,
    first: AtomicBool,
}

impl<const JITTER: u8, const DROP_FIRST: bool> JitterInterface<JITTER, DROP_FIRST> {
    fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            usc: UdpSocketController::bind(addr)?,
            first: AtomicBool::new(false),
        })
    }
}

impl<const JITTER: u8, const DROP_FIRST: bool> QuicInterface
    for JitterInterface<JITTER, DROP_FIRST>
{
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.usc.local_addr()
    }

    fn max_segment_size(&self) -> usize {
        self.usc.max_segment_size()
    }

    fn max_segments(&self) -> usize {
        self.usc.max_segments()
    }

    fn poll_send(
        &self,
        cx: &mut std::task::Context,
        pkts: &[std::io::IoSlice],
        hdr: PacketHeader,
    ) -> std::task::Poll<std::io::Result<usize>> {
        let drop_first = DROP_FIRST
            && self
                .first
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
        let jitter = rand::rng().random::<u8>() < JITTER;
        if drop_first || jitter {
            tracing::warn!(drop_first, jitter, "dropping packet",);
            return std::task::Poll::Ready(Ok(pkts.len()));
        }
        QuicInterface::poll_send(&self.usc, cx, pkts, hdr)
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        pkts: &mut Vec<bytes::BytesMut>,
        hdrs: &mut [PacketHeader],
    ) -> std::task::Poll<std::io::Result<usize>> {
        QuicInterface::poll_recv(&self.usc, cx, pkts, hdrs)
    }
}

fn launch_echo_server<const JITTER: u8, const DROP_FIRST: bool>(
    parameters: ServerParameters,
) -> Result<(Arc<QuicServer>, impl Future<Output: Send>), Error> {
    let server = QuicServer::builder()
        .without_client_cert_verifier()
        .with_single_cert(SERVER_CERT, SERVER_KEY)
        .with_parameters(parameters)
        .with_qlog(QLOGGER.clone())
        .with_iface_factory(JitterInterface::<JITTER, DROP_FIRST>::bind)
        .listen("127.0.0.1:0".parse::<SocketAddr>()?)?;
    Ok((server.clone(), serve_echo(server)))
}

fn launch_test_client<const JITTER: u8, const DROP_FIRST: bool>(
    parameters: ClientParameters,
) -> Arc<QuicClient> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CA_CERT.to_certificate());
    let client = QuicClient::builder()
        .with_root_certificates(roots)
        .with_parameters(parameters)
        .without_cert()
        .with_qlog(QLOGGER.clone())
        .enable_sslkeylog()
        .with_iface_factory(JitterInterface::<JITTER, DROP_FIRST>::bind)
        .build();

    Arc::new(client)
}

#[test]
fn handshake_lost() -> Result<(), Error> {
    let launch_server = || launch_echo_server::<0, true>(server_parameters());
    let launch_client = |server_addr| async move {
        let client = launch_test_client::<0, true>(client_parameters());
        let connection = client.connect("localhost", server_addr)?;
        connection.handshaked().await;
        connection.close("no error".into(), 0);
        time::sleep(Duration::from_secs(1)).await;
        Ok(())
    };
    run_serially(launch_server, launch_client)
}

#[test]
fn parallel_stream() -> Result<(), Error> {
    let launch_server = || launch_echo_server::<16, false>(server_parameters());
    let launch_client = |server_addr| async move {
        let client = launch_test_client::<16, true>(client_parameters());

        let mut streams = JoinSet::new();

        for conn_idx in 0..1 {
            let connection = client.connect("localhost", server_addr)?;
            for stream_idx in 0..PARALLEL_ECHO_STREAMS {
                let connection = connection.clone();
                streams.spawn(
                    async move {
                        send_and_verify_echo(&connection, include_bytes!("lost.rs")).await
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
    run_serially(launch_server, launch_client)
}
