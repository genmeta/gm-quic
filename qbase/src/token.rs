use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use bytes::BufMut;
use futures::io;
use nom::{bytes::complete::take, IResult};
use rand::Rng;

use crate::{
    error::{Error, ErrorKind},
    frame::{BeFrame, NewTokenFrame, ReceiveFrame},
};

const TOKEN_PATH: &str = "/tmp/gm-quic";
const LIFETIME: u64 = 60 * 60 * 24 * 3; // 3 days
pub const RESET_TOKEN_SIZE: usize = 16;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct ResetToken([u8; RESET_TOKEN_SIZE]);

impl ResetToken {
    pub fn new(bytes: &[u8]) -> Self {
        Self(bytes.try_into().unwrap())
    }

    pub fn random_gen() -> Self {
        let mut bytes = [0; RESET_TOKEN_SIZE];
        rand::thread_rng().fill(&mut bytes);
        Self(bytes)
    }

    pub fn encoding_size(&self) -> usize {
        RESET_TOKEN_SIZE
    }
}

pub fn be_reset_token(input: &[u8]) -> IResult<&[u8], ResetToken> {
    let (input, bytes) = take(RESET_TOKEN_SIZE)(input)?;
    Ok((input, ResetToken::new(bytes)))
}

pub trait WriteResetToken {
    fn put_reset_token(&mut self, token: &ResetToken);
}

impl<T: BufMut> WriteResetToken for T {
    fn put_reset_token(&mut self, token: &ResetToken) {
        self.put_slice(token);
    }
}

impl std::ops::Deref for ResetToken {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

type TokenQueue = VecDeque<(Vec<u8>, u64)>;
#[derive(Clone, Debug)]
struct ArcTokenQueue(Arc<Mutex<TokenQueue>>);

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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct Client<RETRY>
where
    RETRY: RetryInitial,
{
    path: String,
    queue: ArcTokenQueue,
    retry: RETRY,
    pub initial_token: Arc<Mutex<Vec<u8>>>,
}

impl<RETRY> Client<RETRY>
where
    RETRY: RetryInitial,
{
    pub fn new(server_name: String, retry: RETRY) -> Self {
        let path = format!("{}/client/{}.json", TOKEN_PATH, server_name);
        let queue = ArcTokenQueue::read(path.as_str()).unwrap_or_else(|_| {
            let queue = Arc::new(Mutex::new(VecDeque::new()));
            ArcTokenQueue(queue)
        });

        let initial_token = queue.pop_back().map(|(token, _)| token).unwrap_or_default();
        Self {
            path,
            queue,
            retry,
            initial_token: Arc::new(Mutex::new(initial_token)),
        }
    }

    // 收到 retry token，后续 initial 包都需要使用这个 token
    pub fn recv_retry_token(&mut self, token: Vec<u8>) {
        *self.initial_token.lock().unwrap() = token;
        self.retry.retry_initial();
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

#[derive(Clone, Debug)]
pub enum TokenRegistry<ISSUED, RETRY>
where
    ISSUED: Extend<NewTokenFrame>,
    RETRY: RetryInitial,
{
    Server(Server<ISSUED>),
    Client(Client<RETRY>),
}

impl<ISSUED, RETRY> TokenRegistry<ISSUED, RETRY>
where
    ISSUED: Extend<NewTokenFrame>,
    RETRY: RetryInitial,
{
    pub fn new_server(server_name: String, issued: ISSUED) -> Self {
        Self::Server(Server::new(server_name, issued))
    }

    pub fn new_client(server_name: String, retry: RETRY) -> Self {
        Self::Client(Client::new(server_name, retry))
    }

    pub fn receive_retry_packet(&mut self, token: Vec<u8>) {
        match self {
            TokenRegistry::Server(_) => unreachable!("Server cannot receive Retry packet"),
            TokenRegistry::Client(client) => client.recv_retry_token(token),
        }
    }
}

impl<ISSUED, RETRY> ReceiveFrame<NewTokenFrame> for TokenRegistry<ISSUED, RETRY>
where
    ISSUED: Extend<NewTokenFrame>,
    RETRY: RetryInitial,
{
    type Output = ();

    fn recv_frame(&mut self, frame: &NewTokenFrame) -> Result<Self::Output, crate::error::Error> {
        match self {
            Self::Server(_) => Err(Error::new(
                ErrorKind::ProtocolViolation,
                frame.frame_type(),
                "Server received NewTokenFrame",
            )),
            Self::Client(client) => {
                client.recv_new_token(frame.token.clone());
                Ok(())
            }
        }
    }
}

pub trait RetryInitial {
    fn retry_initial(&mut self);
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_create_token() {
        super::ResetToken::new(&[0; 16]);
    }

    #[test]
    #[should_panic]
    fn test_creat_token_with_less_size() {
        super::ResetToken::new(&[0; 15]);
    }

    #[test]
    #[should_panic]
    fn test_creat_token_with_more_size() {
        super::ResetToken::new(&[0; 17]);
    }

    #[test]
    fn test_read_reset_token() {
        use nom::error::{Error, ErrorKind};

        let buf = vec![0; 16];
        let (remain, token) = super::be_reset_token(&buf).unwrap();
        assert_eq!(remain.len(), 0);
        assert_eq!(token, super::ResetToken::new(&[0; 16]));
        let buf = vec![0; 15];
        assert_eq!(
            super::be_reset_token(&buf),
            Err(nom::Err::Error(Error::new(&buf[..], ErrorKind::Eof)))
        );
    }

    #[test]
    fn test_write_reset_token() {
        use super::WriteResetToken;

        let mut buf = vec![];
        let token = super::ResetToken::new(&[0; 16]);
        buf.put_reset_token(&token);
        assert_eq!(buf, &[0; 16]);
    }
}
