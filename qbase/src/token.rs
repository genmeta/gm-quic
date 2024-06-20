use bytes::BufMut;
use nom::{bytes::complete::take, IResult};

pub const RESET_TOKEN_SIZE: usize = 16;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct ResetToken([u8; RESET_TOKEN_SIZE]);

impl ResetToken {
    pub fn new(bytes: &[u8]) -> Self {
        Self(bytes.try_into().unwrap())
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
        self.put_slice(&token.0);
    }
}

impl std::ops::Deref for ResetToken {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
