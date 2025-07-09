use clap::Parser;
use qudp::UdpSocketController;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short,long, default_value_t = String::from("127.0.0.1:12345"))]
    bind: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::TRACE)
        .init();

    let args = Args::parse();
    let addr = args.bind.parse().unwrap();

    let socket = UdpSocketController::bind(addr).expect("failed to create socket");
    let mut receiver = socket.receiver();
    loop {
        match receiver.recv().await {
            Ok(n) => {
                tracing::info!(
                    "Received {} packets, dst {}, src {} len {}",
                    n,
                    receiver.headers[0].dst,
                    receiver.headers[0].src,
                    receiver.headers[0].seg_size
                );
            }
            Err(e) => {
                tracing::error!("Receive failed: {}", e);
            }
        }
    }
}
