// NEW_TOKEN Frame {
//   Type (i) = 0x07,
//   Token Length (i),
//   Token (..),
// }

use crate::SpaceId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTokenFrame {
    pub token: Vec<u8>,
}

const NEW_TOKEN_FRAME_TYPE: u8 = 0x07;

impl super::BeFrame for NewTokenFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::NewToken
    }

    fn belongs_to(&self, space_id: SpaceId) -> bool {
        // ___1
        space_id == SpaceId::OneRtt
    }

    fn max_encoding_size(&self) -> usize {
        // token's length could not exceed 20
        1 + 1 + self.token.len()
    }

    fn encoding_size(&self) -> usize {
        1 + 1 + self.token.len()
    }
}

pub(super) mod ext {
    use super::{NewTokenFrame, NEW_TOKEN_FRAME_TYPE};

    // nom parser for NEW_TOKEN_FRAME
    pub fn be_new_token_frame(input: &[u8]) -> nom::IResult<&[u8], NewTokenFrame> {
        use crate::varint::ext::be_varint;
        use nom::bytes::streaming::take;
        use nom::combinator::{flat_map, map};
        flat_map(be_varint, |length| {
            map(take(length.into_inner() as usize), |data: &[u8]| {
                NewTokenFrame {
                    token: data.to_vec(),
                }
            })
        })(input)
    }

    pub trait WriteNewTokenFrame {
        fn put_new_token_frame(&mut self, frame: &NewTokenFrame);
    }

    impl<T: bytes::BufMut> WriteNewTokenFrame for T {
        fn put_new_token_frame(&mut self, frame: &NewTokenFrame) {
            use crate::varint::{ext::WriteVarInt, VarInt};
            self.put_u8(NEW_TOKEN_FRAME_TYPE);
            self.put_varint(&VarInt::from_u32(frame.token.len() as u32));
            self.put_slice(&frame.token);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_read_new_token_frame() {
        use super::ext::be_new_token_frame;
        let buf = vec![0x02, 0x01, 0x02];
        let (input, frame) = be_new_token_frame(&buf).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(frame.token, vec![0x01, 0x02]);
    }

    #[test]
    fn test_write_new_token_frame() {
        use super::ext::WriteNewTokenFrame;
        let mut buf = Vec::<u8>::new();
        let frame = super::NewTokenFrame {
            token: vec![0x01, 0x02],
        };
        buf.put_new_token_frame(&frame);
        assert_eq!(buf, vec![0x07, 0x02, 0x01, 0x02]);
    }
}
