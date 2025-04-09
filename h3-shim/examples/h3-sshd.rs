use std::{
    ffi::{CStr, CString},
    fs::File,
    io::Write,
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd},
    path::PathBuf,
    ptr,
};

use bytes::{Buf, Bytes};
use clap::Parser;
use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use http::{Request, StatusCode};
use libc::c_int;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

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
        short,
        long,
        default_values = ["127.0.0.1:4433", "[::1]:4433"],
        help = "What address:port to listen for new connections"
    )]
    listen: Vec<SocketAddr>,
    #[command(flatten)]
    certs: Certs,
}

#[derive(Parser, Debug)]
struct Certs {
    #[arg(long, short, default_value = "localhost", help = "Server name.")]
    server_name: String,
    #[arg(
        long,
        short,
        default_value = "tests/keychain/localhost/server.cert",
        help = "Certificate for TLS. If present, `--key` is mandatory."
    )]
    cert: PathBuf,
    #[arg(
        long,
        short,
        default_value = "tests/keychain/localhost/server.key",
        help = "Private key for the certificate."
    )]
    key: PathBuf,
}

// static OPTIONS: OnceLock<Options> = OnceLock::new();
static ALPN: &[u8] = b"h3";

#[cfg_attr(test, allow(unused))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    // console_subscriber::init();

    run(Options::parse()).await
}

async fn run(options: Options) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // OPTIONS.set(options);
    let Certs {
        server_name,
        cert,
        key,
    } = options.certs;

    let quic_server = ::gm_quic::QuicServer::builder()
        .with_supported_versions([1u32])
        .without_client_cert_verifier()
        .with_parameters(server_parameters())
        .enable_sni()
        .add_host(server_name, cert.as_path(), key.as_path())
        .with_alpns([ALPN.to_vec()])
        .listen(&options.listen[..])?;
    info!("listen on {:?}", quic_server.addresses());

    // handle incoming connections and requests
    while let Ok((new_conn, _pathway)) = quic_server.accept().await {
        let h3_conn =
            match h3::server::Connection::new(h3_shim::QuicConnection::new(new_conn).await).await {
                Ok(h3_conn) => {
                    info!("accept a new quic connection");
                    h3_conn
                }
                Err(error) => {
                    tracing::error!("failed to establish h3 connection: {}", error);
                    continue;
                }
            };
        tokio::spawn(handle_connection(h3_conn));
    }

    Ok(())
}

fn server_parameters() -> gm_quic::ServerParameters {
    let mut params = gm_quic::ServerParameters::default();

    params.set_initial_max_streams_bidi(100u32);
    params.set_initial_max_streams_uni(100u32);
    params.set_initial_max_data(1u32 << 20);
    params.set_initial_max_stream_data_uni(1u32 << 20);
    params.set_initial_max_stream_data_bidi_local(1u32 << 20);
    params.set_initial_max_stream_data_bidi_remote(1u32 << 20);

    params
}

async fn handle_connection<T>(mut connection: h3::server::Connection<T, Bytes>)
where
    T: h3::quic::Connection<Bytes>,
    <T as h3::quic::OpenStreams<Bytes>>::BidiStream: h3::quic::BidiStream<Bytes> + Send + 'static,
    <<T as h3::quic::OpenStreams<Bytes>>::BidiStream as h3::quic::BidiStream<bytes::Bytes>>::SendStream: Send + 'static,
    <<T as h3::quic::OpenStreams<Bytes>>::BidiStream as h3::quic::BidiStream<bytes::Bytes>>::RecvStream: Send + 'static,
{
    loop {
        match connection.accept().await {
            Ok(Some((request, stream))) => {
                info!(?request, "handle");
                tokio::spawn(async move {
                    if let Err(e) = handle_request(request, stream).await {
                        error!("handling request failed: {}", e);
                    }
                });
            }
            Ok(None) => break,
            Err(error) => match error.get_error_level() {
                ErrorLevel::ConnectionError => break,
                ErrorLevel::StreamError => continue,
            },
        }
    }
}

#[tracing::instrument(skip_all)]
async fn handle_request<T>(
    request: Request<()>,
    mut stream: RequestStream<T, Bytes>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
    <T as h3::quic::BidiStream<bytes::Bytes>>::SendStream: Send + 'static,
    <T as h3::quic::BidiStream<bytes::Bytes>>::RecvStream: Send + 'static,
{
    if request.method() != http::Method::PUT {
        let resp = http::Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(())?;
        stream.send_response(resp).await?;
        stream.finish().await?;
        return Err("Method not allowed".into());
    }
    // 从 Authorization 头获取认证信息
    let auth_header = match request.headers().get("Authorization") {
        Some(value) => value.to_str().unwrap_or_default(),
        None => {
            let resp = http::Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(())?;
            stream.send_response(resp).await?;
            stream.finish().await?;
            return Err("Missing Authorization header".into());
        }
    };

    // 解析 Basic Auth
    use base64::Engine;
    let credentials = match auth_header.strip_prefix("Basic ") {
        Some(b64) => match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => {
                let resp = http::Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(())?;
                stream.send_response(resp).await?;
                stream.finish().await?;
                return Err("Invalid Authorization header".into());
            }
        },
        None => {
            let resp = http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(())?;
            stream.send_response(resp).await?;
            stream.finish().await?;
            return Err("Invalid Authorization header".into());
        }
    };

    let Some((username, password)) = credentials.split_once(':') else {
        let resp = http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(())?;
        stream.send_response(resp).await?;
        stream.finish().await?;
        return Err("Invalid Authorization header".into());
    };

    let resp = http::Response::builder().status(StatusCode::OK).body(())?;
    stream.send_response(resp).await?;

    // 创建PTY
    let mut master: c_int = 0;
    let mut slave: c_int = 0;
    let mut name_buf = [0u8; 64];
    unsafe {
        libc::openpty(
            &mut master as *mut _,
            &mut slave as *mut _,
            name_buf.as_mut_ptr() as *mut _,
            ptr::null_mut(),
            ptr::null_mut(),
        );
    }

    // Fork子进程
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // 子进程
        unsafe {
            libc::close(master);
            libc::login_tty(slave);

            // 设置用户
            let user = CString::new(username).unwrap();
            let pw = libc::getpwnam(user.as_ptr());
            if pw.is_null() {
                println!("User not found");
                libc::exit(1);
            }

            // 暂且先用这种方式校验权限，这种方式不够安全
            // 后续改成quic连接级的证书校验
            if !verify_password(username, password) {
                println!("Authentication failed");
                libc::exit(1);
            }

            // 设置补充组
            libc::initgroups((*pw).pw_name, (*pw).pw_gid as _);
            // 设置gid和uid
            if libc::setgid((*pw).pw_gid) != 0 || libc::setuid((*pw).pw_uid) != 0 {
                eprintln!("Failed to setuid/setgid");
                libc::exit(1);
            }

            // 设置环境变量
            let home = CStr::from_ptr((*pw).pw_dir).to_string_lossy();
            let shell = CStr::from_ptr((*pw).pw_shell).to_string_lossy();
            libc::setenv(
                CString::new("HOME").unwrap().as_ptr(),
                CString::new(home.as_bytes()).unwrap().as_ptr(),
                1,
            );
            libc::setenv(CString::new("USER").unwrap().as_ptr(), user.as_ptr(), 1);
            libc::setenv(
                CString::new("SHELL").unwrap().as_ptr(),
                CString::new(shell.as_bytes()).unwrap().as_ptr(),
                1,
            );

            // 切换工作目录
            if libc::chdir((*pw).pw_dir) != 0 {
                libc::exit(1);
            }

            // 执行shell
            let shell = CString::new(
                CStr::from_ptr((*pw).pw_shell)
                    .to_str()
                    .unwrap_or("/bin/bash"),
            )
            .unwrap();
            libc::execl(
                shell.as_ptr(),
                shell.as_ptr(),
                ptr::null::<libc::c_char>() as *const _,
            );
            libc::exit(0);
        }
    }

    // 主进程
    unsafe { libc::close(slave) };
    // 设置master fd为非阻塞模式
    let pty_master = unsafe {
        let flags = libc::fcntl(master, libc::F_GETFL);
        libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK);
        std::fs::File::from_raw_fd(master as _)
    };

    copy_between_pty_and_stream(pty_master, stream).await;

    Ok(())
}

async fn copy_between_pty_and_stream<T>(mut pty_master: File, stream: RequestStream<T, Bytes>)
where
    T: BidiStream<Bytes>,
    <T as h3::quic::BidiStream<bytes::Bytes>>::SendStream: Send + 'static,
    <T as h3::quic::BidiStream<bytes::Bytes>>::RecvStream: Send + 'static,
{
    let (mut sender, mut recver) = stream.split();

    // 启动读取PTY任务
    let master_fd = pty_master.as_raw_fd();
    let read_task = tokio::spawn(async move {
        let mut read_buf = [0u8; 8192];
        loop {
            match unsafe { libc::read(master_fd, read_buf.as_mut_ptr() as *mut _, read_buf.len()) }
            {
                -1 => {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        tokio::task::yield_now().await;
                        continue;
                    }
                    _ = sender
                        .send_data(Bytes::from(format!("从PTY读取失败: {}", err)))
                        .await
                        .inspect_err(|e| error!("发送错误消息失败: {}", e));
                    break;
                }
                0 => break, // EOF
                n => {
                    let data = Bytes::copy_from_slice(&read_buf[..n as usize]);
                    if let Err(e) = sender.send_data(data).await {
                        error!("发送数据失败: {}", e);
                        break;
                    }
                }
            }
        }
        _ = sender
            .finish()
            .await
            .inspect_err(|e| error!("关闭发送端失败: {}", e));
    });

    // 启动写入PTY任务
    let write_task = tokio::spawn(async move {
        let mut read_buffer = Vec::new();
        while let Ok(Some(data)) = recver.recv_data().await {
            let buf = data.chunk();
            read_buffer.extend_from_slice(buf);

            let mut buf = std::io::Cursor::new(&read_buffer);
            let mut de = serde_json::Deserializer::from_reader(&mut buf);
            loop {
                match TerminalMessage::deserialize(&mut de) {
                    Ok(msg) => {
                        match msg {
                            TerminalMessage::Text(text) => {
                                // 将文本写入PTY
                                if let Err(e) = pty_master.write_all(text.as_bytes()) {
                                    eprintln!("写入PTY失败: {}", e);
                                    recver.stop_sending(h3::error::Code::H3_INTERNAL_ERROR);
                                    return;
                                }
                            }
                            TerminalMessage::WindowSize { rows, cols } => {
                                // 设置PTY窗口大小
                                unsafe {
                                    let winsz = libc::winsize {
                                        ws_row: rows,
                                        ws_col: cols,
                                        ws_xpixel: 0,
                                        ws_ypixel: 0,
                                    };
                                    libc::ioctl(pty_master.as_raw_fd(), libc::TIOCSWINSZ, &winsz);
                                }
                            }
                            TerminalMessage::Signal(signal) => {
                                // 将信号转换为对应的控制字符写入PTY
                                let ctrl_char = match signal {
                                    2 => "\x03", // Ctrl+C (SIGINT)
                                    3 => "\x1A", // Ctrl+Z (SIGTSTP)
                                    _ => return,
                                };
                                if let Err(e) = pty_master.write_all(ctrl_char.as_bytes()) {
                                    eprintln!("写入PTY控制字符失败: {}", e);
                                    recver.stop_sending(h3::error::Code::H3_INTERNAL_ERROR);
                                    return;
                                }
                            }
                            TerminalMessage::ControlSequence(seq) => {
                                // 处理各种控制序列
                                let sequence = match seq.as_str() {
                                    "\x04" => "\x04",       // Ctrl+D (EOF)
                                    "\x7f" => "\x7f",       // Backspace
                                    "\x1b[3~" => "\x1b[3~", // Delete
                                    "\x1b" => "\x1b",       // Esc
                                    "\x1b[A" => "\x1b[A",   // Up
                                    "\x1b[B" => "\x1b[B",   // Down
                                    "\x1b[C" => "\x1b[C",   // Right
                                    "\x1b[D" => "\x1b[D",   // Left
                                    "\x1b[H" => "\x1b[H",   // Home
                                    "\x1b[F" => "\x1b[F",   // End
                                    "\x1b[5~" => "\x1b[5~", // Page Up
                                    "\x1b[6~" => "\x1b[6~", // Page Down
                                    "\t" => "\t",           // Tab
                                    _ => continue,
                                };
                                if let Err(e) = pty_master.write_all(sequence.as_bytes()) {
                                    error!("写入PTY控制序列失败: {}", e);
                                    recver.stop_sending(h3::error::Code::H3_INTERNAL_ERROR);
                                    return;
                                }
                            }
                            TerminalMessage::Heartbeat => {
                                // 心跳包,不需要处理
                                continue;
                            }
                        }
                    }
                    Err(e) if e.is_eof() => {
                        // 保存未处理完的数据
                        let pos = buf.position() as usize;
                        read_buffer.drain(..pos);
                        break;
                    }
                    Err(e) => {
                        // TODO: fetal error
                        eprintln!("JSON解析错误: {}", e);
                        read_buffer.clear();
                        break;
                    }
                }
            }
        }
    });

    // 等待任意一个任务完成
    tokio::select! {
        _ = read_task => {}
        _ = write_task => {}
    }
}

fn verify_password(username: &str, password: &str) -> bool {
    #[cfg(unix)]
    return {
        let mut auth = pam::Authenticator::with_password("login").expect("Init pam failed");
        auth.get_handler().set_credentials(username, password);
        if let Err(e) = auth.authenticate() {
            println!("Authentication failed: {}", e);
            return false;
        }
        true
    };

    #[allow(unreachable_code)]
    false
}
