use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use futures::io;

use crate::{frame::NewTokenFrame, streamid::Role};

const TOKEN_PATH: &str = "/tmp/gm-quic";
const LIFETIME: u64 = 60 * 60 * 24 * 3; // 3 days

#[derive(Clone)]
struct ArcTokenQueue(Arc<Mutex<VecDeque<(Vec<u8>, u64)>>>);

impl ArcTokenQueue {
    fn remove_expired(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let mut queue = self.0.lock().unwrap();
        queue.retain(|(_, exp)| exp > &now);
    }

    fn contains(&self, token: &[u8]) -> bool {
        let queue = self.0.lock().unwrap();
        queue.iter().any(|(t, _)| t == token)
    }

    fn flush(&self, _: &str) {
        todo!("Write token file to disk and serialize it from a TokenQueue")
    }

    fn read(_: &str) -> io::Result<Self> {
        todo!("Read token file from disk and deserialize it into a TokenQueue")
    }

    fn push_back(&self, token: (Vec<u8>, u64)) {
        let mut queue = self.0.lock().unwrap();
        queue.push_back(token);
    }

    fn pop_back(&self) -> Option<(Vec<u8>, u64)> {
        let mut queue = self.0.lock().unwrap();
        queue.pop_back()
    }
}

#[derive(Clone)]
pub struct Server<ISSUED>
where
    ISSUED: Extend<NewTokenFrame>,
{
    path: String,
    issued: ISSUED,
    queue: ArcTokenQueue,
    retry_token: Option<Vec<u8>>,
}

impl<ISSUED> Server<ISSUED>
where
    ISSUED: Extend<NewTokenFrame>,
{
    pub fn new(name: String, issued: ISSUED) -> Self {
        let path = format!("{}/server/{}.json", TOKEN_PATH, name);
        let queue = ArcTokenQueue::read(path.as_str()).unwrap_or_else(|_| {
            let queue = Arc::new(Mutex::new(VecDeque::new()));
            ArcTokenQueue(queue)
        });

        Self {
            path,
            issued,
            queue,
            retry_token: None,
        }
    }

    pub fn issue_new_token(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let exp = now + LIFETIME;

        let token = rand::random::<[u8; 16]>();
        self.queue.push_back((token.to_vec(), exp));
        self.issued.extend([NewTokenFrame {
            token: token.to_vec(),
        }]);
        self.queue.flush(self.path.as_str());
    }

    // 如果发过 Retry 包，校验 Retry Token，否则校验 new token
    pub fn validate(&mut self, token: &[u8]) -> bool {
        if let Some(retry_token) = &self.retry_token {
            if token == retry_token {
                return true;
            }
            return false;
        }
        self.queue.remove_expired();
        self.queue.contains(token)
    }

    pub fn send_retry_token(&mut self, token: Vec<u8>) {
        self.retry_token = Some(token);
    }
}

#[derive(Clone)]
pub struct Client {
    path: String,
    queue: ArcTokenQueue,
    pub initial_token: Arc<Mutex<Vec<u8>>>,
}

impl Client {
    pub fn new(server_name: String) -> Self {
        let path = format!("{}/client/{}.json", TOKEN_PATH, server_name);
        let queue = ArcTokenQueue::read(path.as_str()).unwrap_or_else(|_| {
            let queue = Arc::new(Mutex::new(VecDeque::new()));
            ArcTokenQueue(queue)
        });

        let initial_token = queue.pop_back().map(|(token, _)| token).unwrap_or_default();
        Self {
            path,
            queue,
            initial_token: Arc::new(Mutex::new(initial_token)),
        }
    }

    // 收到 retry token，后续 initial 包都需要使用这个 token
    pub fn recv_retry_token(&mut self, token: Vec<u8>) {
        *self.initial_token.lock().unwrap() = token;
    }

    pub fn recv_new_token(&mut self, token: Vec<u8>) {
        let queue = &mut self.queue;
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
            + LIFETIME;

        queue.push_back((token, exp));
        queue.remove_expired();
        queue.flush(self.path.as_str());
    }
}

#[derive(Clone)]
pub enum TokenRegistry<ISSUED>
where
    ISSUED: Extend<NewTokenFrame>,
{
    Server(Server<ISSUED>),
    Client(Client),
}

impl<ISSUED> TokenRegistry<ISSUED>
where
    ISSUED: Extend<NewTokenFrame>,
{
    pub fn new(role: Role, server_name: String, issued: ISSUED) -> Self {
        match role {
            Role::Server => Self::Server(Server::new(server_name, issued)),
            Role::Client => Self::Client(Client::new(server_name)),
        }
    }
}
