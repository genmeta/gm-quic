use clap::Parser;
use qudp::ArcUsc;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short,long, default_value_t = String::from("[::]:12345"))]
    bind: String,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();
    let addr = args.bind.parse().unwrap();

    let socket = ArcUsc::new(addr).expect("failed to create socket");
    loop {
        let mut receiver = socket.receiver();
        let n = (&mut receiver).await;
        match n {
            Ok(n) => {
                println!("received {} packets ", n)
            }
            Err(e) => {
                println!("error: {}", e)
            }
        }
    }
}
