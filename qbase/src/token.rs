use std::sync::{Arc, Mutex, MutexGuard};

use bytes::BufMut;
use nom::{bytes::complete::take, IResult};
use rand::Rng;

use crate::{
    error::{Error, ErrorKind},
    frame::{BeFrame, NewTokenFrame, ReceiveFrame},
};

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

pub trait TokenSink: Send + Sync {
    fn sink(&self, server_name: &str, token: Vec<u8>);

    fn get_token(&self, server_name: &str) -> Vec<u8>;
}

pub trait TokenProvider: Send + Sync {
    fn provide_new_token(&self, server_name: &str) -> Vec<u8>;

    fn provide_retry_token(&self, server_name: &str) -> Vec<u8>;

    // A token sent in a NEW_TOKEN frame or a Retry packet MUST be constructed in
    // a way that allows the server to identify how it was provided to a client
    fn validate_token(&self, server_name: String, token: &[u8]) -> bool;
}

#[derive(Clone)]
pub struct ArcTokenRegistry(Arc<Mutex<TokenRegistry>>);

impl ArcTokenRegistry {
    pub fn default_sink(server_name: String) -> Self {
        Self(Arc::new(Mutex::new(TokenRegistry::Client((
            server_name,
            Arc::new(DefaultTokenRegistry),
        )))))
    }

    pub fn default_provider() -> Self {
        Self(Arc::new(Mutex::new(TokenRegistry::Server(Arc::new(
            DefaultTokenRegistry,
        )))))
    }

    pub fn with_sink(server_name: String, client: Arc<dyn TokenSink>) -> Self {
        Self(Arc::new(Mutex::new(TokenRegistry::Client((
            server_name,
            client,
        )))))
    }

    pub fn with_provider(provider: Arc<dyn TokenProvider>) -> Self {
        Self(Arc::new(Mutex::new(TokenRegistry::Server(provider))))
    }

    pub fn lock_guard(&self) -> MutexGuard<TokenRegistry> {
        self.0.lock().unwrap()
    }
}
pub enum TokenRegistry {
    Client((String, Arc<dyn TokenSink>)),
    Server(Arc<dyn TokenProvider>),
}

impl ReceiveFrame<NewTokenFrame> for ArcTokenRegistry {
    type Output = ();

    fn recv_frame(&self, frame: &NewTokenFrame) -> Result<Self::Output, crate::error::Error> {
        let guard = self.0.lock().unwrap();
        match &*guard {
            TokenRegistry::Client((server_name, client)) => {
                client.sink(server_name, frame.token.clone());
                Ok(())
            }
            TokenRegistry::Server(_) => Err(Error::new(
                ErrorKind::ProtocolViolation,
                frame.frame_type(),
                "Server received NewTokenFrame",
            )),
        }
    }
}

struct DefaultTokenRegistry;

impl TokenSink for DefaultTokenRegistry {
    fn sink(&self, _: &str, _: Vec<u8>) {}

    fn get_token(&self, _: &str) -> Vec<u8> {
        Vec::new()
    }
}

impl TokenProvider for DefaultTokenRegistry {
    fn provide_new_token(&self, _: &str) -> Vec<u8> {
        Vec::new()
    }

    fn provide_retry_token(&self, _: &str) -> Vec<u8> {
        Vec::new()
    }

    fn validate_token(&self, _: String, _: &[u8]) -> bool {
        false
    }
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
