use derive_more::Deref;

use crate::varint::{VarInt, WriteVarInt, be_varint};

/// NEW_TOKEN frame.
///
/// ```text
/// NEW_TOKEN Frame {
///   Type (i) = 0x07,
///   Token Length (i),
///   Token (..),
/// }
/// ```
///
/// See [NEW_TOKEN Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-new_token-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Deref, Debug, Clone, PartialEq, Eq)]
pub struct NewTokenFrame {
    #[deref]
    token: Vec<u8>,
}

const NEW_TOKEN_FRAME_TYPE: u8 = 0x07;

impl super::GetFrameType for NewTokenFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::NewToken
    }
}

impl super::EncodeSize for NewTokenFrame {
    fn max_encoding_size(&self) -> usize {
        // token's length could not exceed 20
        1 + 1 + self.token.len()
    }

    fn encoding_size(&self) -> usize {
        1 + 1 + self.token.len()
    }
}

impl NewTokenFrame {
    /// Create a new [`NewTokenFrame`] with the given token.
    pub fn new(token: Vec<u8>) -> Self {
        Self { token }
    }

    /// Create a new [`NewTokenFrame`] from the given token slice.
    pub fn from_slice(token: &[u8]) -> Self {
        Self {
            token: token.to_vec(),
        }
    }

    /// Return the token of the frame.
    pub fn token(&self) -> &[u8] {
        &self.token
    }
}

/// Parse a NEW_TOKEN frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_new_token_frame(input: &[u8]) -> nom::IResult<&[u8], NewTokenFrame> {
    use nom::{
        Parser,
        bytes::streaming::take,
        combinator::{flat_map, map},
    };
    flat_map(be_varint, |length| {
        map(
            take(length.into_inner() as usize),
            NewTokenFrame::from_slice,
        )
    })
    .parse(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<NewTokenFrame> for T {
    fn put_frame(&mut self, frame: &NewTokenFrame) {
        self.put_u8(NEW_TOKEN_FRAME_TYPE);
        self.put_varint(&VarInt::from_u32(frame.token.len() as u32));
        self.put_slice(&frame.token);
    }
}
#[cfg(test)]
mod tests {
    use crate::frame::{EncodeSize, FrameType, GetFrameType, io::WriteFrame};

    #[test]
    fn test_new_token_frame() {
        let frame = super::NewTokenFrame::new(vec![0x01, 0x02]);
        assert_eq!(frame.frame_type(), FrameType::NewToken);
        assert_eq!(frame.max_encoding_size(), 1 + 1 + 2);
        assert_eq!(frame.encoding_size(), 1 + 1 + 2);
    }

    #[test]
    fn test_read_new_token_frame() {
        use super::be_new_token_frame;
        let buf = vec![0x02, 0x01, 0x02];
        let (input, frame) = be_new_token_frame(&buf).unwrap();
        assert!(input.is_empty());
        assert_eq!(frame.token, vec![0x01, 0x02]);
    }

    #[test]
    fn test_write_new_token_frame() {
        let mut buf = Vec::<u8>::new();
        let frame = super::NewTokenFrame::from_slice(&[0x01, 0x02]);
        buf.put_frame(&frame);
        assert_eq!(buf, vec![0x07, 0x02, 0x01, 0x02]);
    }
}
