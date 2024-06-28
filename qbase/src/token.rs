use bytes::BufMut;
use nom::{bytes::complete::take, IResult};
use rand::Rng;

pub const RESET_TOKEN_SIZE: usize = 16;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
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
