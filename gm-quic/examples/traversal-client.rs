// use std::{io, net::SocketAddr};

// use clap::Parser;
// use gm_quic::{
//     prelude::{
//         Connection, EndpointAddr, ParameterId, QuicClient, SocketEndpointAddr, handy::ToCertificate,
//     },
//     qbase::param::ClientParameters,
//     qtraversal::iface::TraversalFactory,
// };
// use rustls::RootCertStore;
// use tokio::{
//     io::{AsyncReadExt, AsyncWriteExt},
//     task::JoinSet,
// };
// use tracing::{info, warn};
// use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// #[derive(Parser)]
// struct Options {
//     #[arg(long)]
//     bind1: SocketAddr,
//     #[arg(long)]
//     bind2: SocketAddr,
//     #[arg(long)]
//     server_outer: SocketAddr,
//     #[arg(long)]
//     server_agent: SocketAddr,
//     #[arg(long, default_value = "nat.genmeta.net:20004")]
//     stun_server: String,
// }

// pub type Error = Box<dyn std::error::Error + Send + Sync>;

// #[tokio::main]
// pub async fn main() -> io::Result<()> {
//     init_logger()?;
//     let default_panic = std::panic::take_hook();
//     std::panic::set_hook(Box::new(move |info| {
//         default_panic(info);
//         info!("panic: {}", info);
//         std::process::exit(1);
//     }));
//     let ops = Options::parse();
//     let server_ep = EndpointAddr::Socket(SocketEndpointAddr::Agent {
//         agent: ops.server_agent,
//         outer: ops.server_outer,
//     });

//     let mut roots = RootCertStore::empty();
//     roots.add_parsable_certificates(
//         include_bytes!("../../../tests/keychain/localhost/ca.cert").to_certificate(),
//     );

//     let stun_servers: Vec<SocketAddr> = tokio::net::lookup_host(&ops.stun_server).await?.collect();
//     if stun_servers.is_empty() {
//         return Err(io::Error::other("failed to resolve stun server"));
//     }

//     let factory = TraversalFactory::initialize_global(stun_servers).unwrap();
//     let client = QuicClient::builder()
//         .with_root_certificates(roots)
//         .without_cert()
//         .enable_sslkeylog()
//         // .with_qlog(Arc::new(DefaultSeqLogger::new(PathBuf::from("qlog"))))
//         .with_iface_factory(factory.as_ref().clone())
//         .with_parameters(client_stream_unlimited_parameters())
//         .bind(&[ops.bind1, ops.bind2][..])
//         .await
//         .build();

//     let mut handle_set = JoinSet::new();
//     for _ in 0..1 {
//         info!(
//             "server ep {:?}, bind {} {}",
//             server_ep, ops.bind1, ops.bind2
//         );
//         let connection = client
//             .connected_to("localhost", [server_ep])
//             .await
//             .map_err(io::Error::other)?;

//         const DATA: &[u8] = include_bytes!("./client.rs");
//         handle_set.spawn(async move {
//             send_and_verify_echo(&connection, DATA).await.unwrap();
//             // 等待打洞结束
//             tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
//             warn!("finish one connection");
//         });
//     }
//     let _et = handle_set.join_all().await;
//     Ok(())
// }

// async fn send_and_verify_echo(connection: &Connection, data: &[u8]) -> Result<(), Error> {
//     let (_sid, (mut reader, mut writer)) = connection.open_bi_stream().await?.unwrap();
//     tracing::debug!("stream opened");

//     let mut back = Vec::new();
//     tokio::try_join!(
//         async {
//             writer.write_all(data).await?;
//             writer.shutdown().await?;
//             tracing::info!("xxxxx write done");
//             Result::<(), Error>::Ok(())
//         },
//         async {
//             reader.read_to_end(&mut back).await?;
//             assert_eq!(back, data);
//             tracing::info!("xxxx read done");
//             Result::<(), Error>::Ok(())
//         }
//     )
//     .map(|_| ())
// }

// fn client_stream_unlimited_parameters() -> ClientParameters {
//     let mut params = ClientParameters::default();
//     _ = params.set(ParameterId::ActiveConnectionIdLimit, 10u32);
//     _ = params.set(ParameterId::InitialMaxData, 1u32 << 20);
//     _ = params.set(ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 20);
//     _ = params.set(ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 20);
//     _ = params.set(ParameterId::InitialMaxStreamDataUni, 1u32 << 20);
//     _ = params.set(ParameterId::InitialMaxStreamsBidi, 100u32);
//     _ = params.set(ParameterId::InitialMaxStreamsUni, 100u32);
//     params
// }

// pub fn init_logger() -> std::io::Result<()> {
//     let filter = tracing_subscriber::filter::filter_fn(|metadata| {
//         !metadata.target().contains("netlink_packet_route")
//     });

//     let _ = tracing_subscriber::registry()
//         .with(tracing_subscriber::Layer::with_filter(
//             tracing_subscriber::fmt::layer()
//                 .with_target(true)
//                 .with_ansi(false)
//                 .with_file(true)
//                 .with_line_number(true),
//             filter,
//         ))
//         .try_init();
//     Ok(())
// }

fn main() {}
