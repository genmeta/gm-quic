use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, LazyLock, Once},
    time::Duration,
};

use gm_quic::QuicServer;
use tokio::{runtime::Runtime, sync::Mutex, time};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[allow(unused)]
pub fn run_serially<C, S>(
    launch_server: impl FnOnce() -> Result<(Arc<QuicServer>, S), Error>,
    launch_client: impl FnOnce(SocketAddr) -> C,
) -> Result<(), Error>
where
    C: Future<Output = Result<(), Error>> + 'static,
    S: Future<Output: Send> + Send + 'static,
{
    static SUBSCRIBER: Once = Once::new();

    SUBSCRIBER.call_once(|| {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init()
    });

    static RT: LazyLock<Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create runtime")
    });

    RT.block_on(async move {
        static LOCK: LazyLock<Arc<Mutex<()>>> = LazyLock::new(Default::default);
        let _lock = LOCK.lock().await;

        let (server, server_task) = launch_server()?;
        let server_task = tokio::task::spawn(server_task);
        let server_addr = *server.addresses().iter().next().expect("no address");
        time::timeout(Duration::from_secs(10), launch_client(server_addr))
            .await
            .expect("test timeout")?;
        server.shutdown();
        server_task.abort();
        Ok(())
    })
}

// TODO
