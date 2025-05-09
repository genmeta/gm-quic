use std::{io::Write, path::PathBuf, time::Duration};

use bytes::Buf;
use clap::Parser;
use crossterm::{
    event::{self, Event, EventStream, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{self},
};
use futures::{SinkExt, StreamExt, channel::mpsc};
use gm_quic::ToCertificate;
use http::uri::Authority;
use serde::{Deserialize, Serialize};
use tracing::info;

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
#[command(name = "server")]
struct Options {
    #[arg(
        long,
        short,
        default_value = "tests/keychain/localhost/ca.cert",
        help = "Certificate of CA who issues the server certificate"
    )]
    ca: PathBuf,

    #[arg(help = "user:password@host:port")]
    auth: Authority,
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

async fn run(options: Options) -> Result<(), Box<dyn core::error::Error + Send + Sync>> {
    let mut username_password = options
        .auth
        .as_str()
        .split('@')
        .next()
        .ok_or("missing user@password")?
        .split(':');
    let username = username_password.next().ok_or("missing username")?;
    let password = match username_password.next() {
        Some(password) => password.to_string(),
        None => rpassword::prompt_password(format!("Please input password for {username}: "))
            .map_err(|e| format!("failed to read password: {e}"))?,
    };

    // 创建通道用于异步通信
    let (tx, mut rx) = mpsc::channel::<TerminalMessage>(32);

    // 启动事件监听任务
    let event_task = tokio::spawn({
        let mut tx = tx.clone();
        async move {
            let (cols, rows) = terminal::size().unwrap();
            _ = tx.send(TerminalMessage::WindowSize { rows, cols }).await;
            let mut events = EventStream::new();
            while let Some(Ok(event)) = events.next().await {
                match event {
                    Event::Resize(cols, rows) => {
                        _ = tx.send(TerminalMessage::WindowSize { rows, cols }).await;
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

    let uri = http::Uri::builder()
        .scheme("https")
        .authority(options.auth.clone())
        .path_and_query("/ssh")
        .build()
        .map_err(|e| format!("failed to build uri: {e}"))?;

    // 构建 Basic Auth 头
    use base64::Engine;

    let credentials = format!("{username}:{password}");
    let b64_encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
    let auth_header = format!("Basic {b64_encoded}");

    let port = options.auth.port_u16().unwrap_or(443);
    let addr = tokio::net::lookup_host((options.auth.host(), port))
        .await?
        .next()
        .ok_or("dns found no addresses")?;
    info!("resolved {:?} to address: {:?}", uri, addr);

    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(options.ca.to_certificate());

    let quic_client = ::gm_quic::QuicClient::builder()
        .with_root_certificates(roots)
        .without_cert()
        .with_alpns([ALPN])
        .with_parameters(client_parameters())
        .enable_sslkeylog()
        .build();
    info!(server_name = options.auth.host(), %addr, "connect to server");
    let conn = quic_client.connect(options.auth.host(), addr)?;

    // create h3 client
    let gm_quic_conn = h3_shim::QuicConnection::new(conn).await;
    let (mut conn, mut h3_client) = h3::client::new(gm_quic_conn).await?;
    let conn_close_monitor = conn.wait_idle();

    info!(%uri, "request");
    let request = http::Request::builder()
        .method("PUT")
        .uri(uri)
        .header("Authorization", auth_header)
        .body(())?;

    // sending request results in a bidirectional stream,
    // which is also used for receiving response
    let mut stream = h3_client.send_request(request).await?;
    let response = stream.recv_response().await?;
    info!(?response, "received");

    // 初始化终端
    // execute!(std::io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    terminal::enable_raw_mode()?;

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
                            eprintln!("Write error: {e}");
                            break;
                        }
                    } else {
                        if let Err(e) = sender.finish().await {
                            eprintln!("Finish error: {e}");
                        }
                        break;
                    }
                }
                _ = interval.tick() => {
                    let serialized = serde_json::to_vec(&TerminalMessage::Heartbeat).unwrap();
                    if let Err(e) = sender.send_data(serialized.into()).await {
                        eprintln!("Heartbeat channel error: {e}");
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
                        eprintln!("Read error: {e}");
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
        eprintln!("Error: {e}");
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
