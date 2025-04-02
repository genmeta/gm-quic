use std::{io::Write, net::SocketAddr, path::PathBuf, time::Duration};

use bytes::Buf;
use clap::Parser;
use crossterm::{
    event::{self, Event, EventStream, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{self},
};
use futures::{SinkExt, StreamExt, channel::mpsc, future};
use gm_quic::ToCertificate;
use serde::{Deserialize, Serialize};
use tracing::{info, trace};

static ALPN: &[u8] = b"h3";

// 定义客户端与服务器通信的消息结构
#[derive(Serialize, Deserialize, Debug)]
enum TerminalMessage {
    Text(String),
    WindowSize { rows: u16, cols: u16 },
    Signal(i32),
    ControlSequence(String),
    Heartbeat,
}

#[derive(Parser, Debug)]
#[structopt(name = "server")]
pub struct Options {
    #[structopt(
        long,
        short,
        default_value = "h3-shim/examples/ca.cert",
        help = "Certificate of CA who issues the server certificate"
    )]
    ca: PathBuf,

    #[structopt(long, short = 'b', default_value = "[::]:0")]
    bind: Vec<SocketAddr>,
    #[structopt(long, short = 'H', help = "host:port")]
    host: String,

    #[structopt(long, short = 'u', help = "Username for SSH authentication")]
    username: String,
    #[structopt(
        long,
        short = 'p',
        default_value = None,
        help = "Password for SSH authentication"
    )]
    password: Option<String>,
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
    // 初始化终端
    // execute!(std::io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    terminal::enable_raw_mode()?;

    // 创建通道用于异步通信
    let (tx, mut rx) = mpsc::channel::<TerminalMessage>(32);

    // 启动事件监听任务
    let event_task = tokio::spawn({
        let mut tx = tx.clone();
        async move {
            let (cols, rows) = terminal::size().unwrap();
            _ = tx
                .send(TerminalMessage::WindowSize {
                    rows: rows as u16,
                    cols: cols as u16,
                })
                .await;
            let mut events = EventStream::new();
            while let Some(Ok(event)) = events.next().await {
                match event {
                    Event::Resize(cols, rows) => {
                        _ = tx
                            .send(TerminalMessage::WindowSize {
                                rows: rows as u16,
                                cols: cols as u16,
                            })
                            .await;
                    }
                    Event::Key(KeyEvent {
                        code, modifiers, ..
                    }) => {
                        let result = match (code, modifiers) {
                            // Control 组合键
                            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                                tx.send(TerminalMessage::Signal(2)).await
                            }
                            (KeyCode::Char('z'), KeyModifiers::CONTROL) => {
                                tx.send(TerminalMessage::Signal(20)).await
                            }
                            (KeyCode::Char('d'), KeyModifiers::CONTROL) => {
                                tx.send(TerminalMessage::ControlSequence("\x04".to_string()))
                                    .await
                            }
                            // 普通字符输入
                            (KeyCode::Char(c), _) => {
                                while let Ok(true) = event::poll(Duration::from_millis(0)) {
                                    let _ = event::read();
                                }
                                tx.send(TerminalMessage::Text(c.to_string())).await
                            }
                            // 特殊键
                            (KeyCode::Enter, _) => {
                                while let Ok(true) = event::poll(Duration::from_millis(0)) {
                                    let _ = event::read();
                                }
                                tx.send(TerminalMessage::Text("\n".to_string())).await
                            }
                            (KeyCode::Tab, _) => {
                                tx.send(TerminalMessage::Text("\t".to_string())).await
                            }
                            (KeyCode::Backspace, _) => {
                                tx.send(TerminalMessage::ControlSequence("\x7f".to_string()))
                                    .await
                            }
                            (KeyCode::Delete, _) => {
                                tx.send(TerminalMessage::ControlSequence("\x1b[3~".to_string()))
                                    .await
                            }
                            (KeyCode::Esc, _) => {
                                tx.send(TerminalMessage::ControlSequence("\x1b".to_string()))
                                    .await
                            }
                            // 方向键
                            (KeyCode::Up, _) => {
                                tx.send(TerminalMessage::ControlSequence("\x1b[A".to_string()))
                                    .await
                            }
                            (KeyCode::Down, _) => {
                                tx.send(TerminalMessage::ControlSequence("\x1b[B".to_string()))
                                    .await
                            }
                            (KeyCode::Right, _) => {
                                tx.send(TerminalMessage::ControlSequence("\x1b[C".to_string()))
                                    .await
                            }
                            (KeyCode::Left, _) => {
                                tx.send(TerminalMessage::ControlSequence("\x1b[D".to_string()))
                                    .await
                            }
                            // Home/End 键
                            (KeyCode::Home, _) => {
                                tx.send(TerminalMessage::ControlSequence("\x1b[H".to_string()))
                                    .await
                            }
                            (KeyCode::End, _) => {
                                tx.send(TerminalMessage::ControlSequence("\x1b[F".to_string()))
                                    .await
                            }
                            // Page Up/Down
                            (KeyCode::PageUp, _) => {
                                tx.send(TerminalMessage::ControlSequence("\x1b[5~".to_string()))
                                    .await
                            }
                            (KeyCode::PageDown, _) => {
                                tx.send(TerminalMessage::ControlSequence("\x1b[6~".to_string()))
                                    .await
                            }
                            _ => Ok(()),
                        };
                        if result.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let path_and_query = format!(
        "/ssh/{}{}",
        options.username,
        options
            .password
            .map_or("".to_string(), |p| format!("?password={}", p)),
    );
    let uri = http::Uri::builder()
        .scheme("https")
        .authority(options.host)
        .path_and_query(path_and_query)
        .build()
        .map_err(|e| format!("failed to build uri: {}", e))?;

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
        .enable_sslkeylog()
        .bind(&options.bind[..])?
        .build();
    info!(%addr, "connect to server");
    let conn = quic_client.connect(auth.host(), addr)?;

    // create h3 client
    let gm_quic_conn = h3_shim::QuicConnection::new(conn).await;
    let (mut conn, mut h3_client) = h3::client::new(gm_quic_conn).await?;
    let conn_close_monitor = async move {
        future::poll_fn(|cx| conn.poll_close(cx)).await?;
        // tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok::<_, Box<dyn std::error::Error + 'static + Send + Sync>>(())
    };

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
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                msg = rx.next() => {
                    if let Some(msg) = msg {
                        let serialized = serde_json::to_vec(&msg).unwrap();
                        if let Err(e) = sender.send_data(serialized.into()).await {
                            eprintln!("Write error: {}", e);
                            break;
                        }
                    } else {
                        if let Err(e) = sender.finish().await {
                            eprintln!("Finish error: {}", e);
                        }
                        break;
                    }
                }
                _ = interval.tick() => {
                    let serialized = serde_json::to_vec(&TerminalMessage::Heartbeat).unwrap();
                    if let Err(e) = sender.send_data(serialized.into()).await {
                        eprintln!("Heartbeat channel error: {}", e);
                        break;
                    }
                }
            }
        }
    });

    let recv_task = tokio::spawn({
        let mut tx = tx.clone();
        async move {
            let stdout = std::io::stdout();
            loop {
                match receiver.recv_data().await {
                    Ok(Some(chunk)) => {
                        let response = String::from_utf8_lossy(chunk.chunk());
                        execute!(stdout.lock(), crossterm::style::Print(response)).unwrap();
                        stdout.lock().flush().unwrap();
                    }
                    Ok(None) => {
                        break;
                    }
                    Err(e) => {
                        eprintln!("Read error: {}", e);
                        receiver.stop_sending(h3::error::Code::H3_NO_ERROR);
                        break;
                    }
                }
            }
            // 接收关闭了，连带着发送也关闭
            tx.close_channel();
        }
    });

    // 等待所有任务完成（通常不会主动退出）
    tokio::select! {
        _ = event_task => (),
        // _ = window_task => (),
        _ = conn_close_monitor => (),
    }

    if let Err(e) = tokio::try_join!(send_task, recv_task) {
        eprintln!("Error: {}", e);
    }

    // 清理
    // execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal::disable_raw_mode()?;

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
