use libc::c_int;
use std::{ffi::CString, net::SocketAddr, path::PathBuf, ptr};

use bytes::{Buf, Bytes};
use clap::Parser;
use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use http::{Request, StatusCode};
use tracing::{error, info};

#[derive(Parser, Debug)]
#[structopt(name = "server")]
pub struct Options {
    #[structopt(
        name = "dir",
        short,
        long,
        help = "Root directory of the files to serve. \
                If omitted, server will respond OK.",
        default_value = "./"
    )]
    pub root: PathBuf,

    #[structopt(
        short,
        long,
        default_values = ["127.0.0.1:4433", "[::1]:4433"],
        help = "What address:port to listen for new connections"
    )]
    pub listen: Vec<SocketAddr>,

    #[structopt(flatten)]
    pub certs: Certs,
}

#[derive(Parser, Debug)]
pub struct Certs {
    #[structopt(
        long,
        short,
        default_value = "h3-shim/examples/server.cert",
        help = "Certificate for TLS. If present, `--key` is mandatory."
    )]
    pub cert: PathBuf,

    #[structopt(
        long,
        short,
        default_value = "h3-shim/examples/server.key",
        help = "Private key for the certificate."
    )]
    pub key: PathBuf,
}

// static OPTIONS: OnceLock<Options> = OnceLock::new();
static ALPN: &[u8] = b"h3";

#[cfg_attr(test, allow(unused))]
#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(true)
        .init();
    // console_subscriber::init();

    run(Options::parse()).await
}

pub async fn run(options: Options) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // OPTIONS.set(options);
    info!("serving {}", options.root.display());
    let Certs { cert, key } = options.certs;

    let quic_server = ::gm_quic::QuicServer::builder()
        .with_supported_versions([1u32])
        .without_client_cert_verifier()
        .with_parameters(server_parameters())
        .enable_sni()
        .add_host("localhost", cert.as_path(), key.as_path())
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
    _request: Request<()>,
    mut stream: RequestStream<T, Bytes>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
    <T as h3::quic::BidiStream<bytes::Bytes>>::SendStream: Send + 'static,
    <T as h3::quic::BidiStream<bytes::Bytes>>::RecvStream: Send + 'static,
{
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
            let pw = libc::getpwnam(CString::new("luffy").unwrap().as_ptr());
            if pw.is_null() {
                // TODO: 用户不存在, send_stream
                libc::exit(1);
            }
            libc::setgid((*pw).pw_gid);
            libc::setuid((*pw).pw_uid);

            // 执行shell
            let shell = CString::new(
                std::ffi::CStr::from_ptr((*pw).pw_shell)
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
    unsafe {
        let flags = libc::fcntl(master, libc::F_GETFL);
        libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    copy_between_pty_and_stream(master, stream).await;

    unsafe { libc::close(master) };

    Ok(())
}

async fn copy_between_pty_and_stream<T>(master_fd: c_int, stream: RequestStream<T, Bytes>)
where
    T: BidiStream<Bytes>,
    <T as h3::quic::BidiStream<bytes::Bytes>>::SendStream: Send + 'static,
    <T as h3::quic::BidiStream<bytes::Bytes>>::RecvStream: Send + 'static,
{
    let (mut sender, mut recver) = stream.split();

    // 启动读取PTY任务
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
        while let Ok(Some(data)) = recver.recv_data().await {
            let buf = data.chunk();
            let mut written = 0;
            while written < buf.len() {
                match unsafe {
                    libc::write(
                        master_fd,
                        buf[written..].as_ptr() as *const _,
                        buf.len() - written,
                    )
                } {
                    -1 => {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        error!("写入PTY失败: {}", err);
                        recver.stop_sending(h3::error::Code::H3_INTERNAL_ERROR);
                        return;
                    }
                    n if n > 0 => written += n as usize,
                    _ => {
                        error!("写入PTY时发生未知错误");
                        recver.stop_sending(h3::error::Code::H3_INTERNAL_ERROR);
                        return;
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
