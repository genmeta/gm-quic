// NEW_TOKEN Frame {
//   Type (i) = 0x07,
//   Token Length (i),
//   Token (..),
// }

use crate::{
    packet::r#type::Type,
    varint::{be_varint, VarInt, WriteVarInt},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTokenFrame {
    pub token: Vec<u8>,
}

const NEW_TOKEN_FRAME_TYPE: u8 = 0x07;

impl super::BeFrame for NewTokenFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::NewToken
    }

    fn belongs_to(&self, packet_type: Type) -> bool {
        use crate::packet::r#type::short::OneRtt;
        // ___1
        matches!(packet_type, Type::Short(OneRtt(_)))
    }

    fn max_encoding_size(&self) -> usize {
        // token's length could not exceed 20
        1 + 1 + self.token.len()
    }

    fn encoding_size(&self) -> usize {
        1 + 1 + self.token.len()
    }
}

// nom parser for NEW_TOKEN_FRAME
pub fn be_new_token_frame(input: &[u8]) -> nom::IResult<&[u8], NewTokenFrame> {
    use nom::{
        bytes::streaming::take,
        combinator::{flat_map, map},
    };
    flat_map(be_varint, |length| {
        map(take(length.into_inner() as usize), |data: &[u8]| {
            NewTokenFrame {
                token: data.to_vec(),
            }
        })
    })(input)
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
    use crate::frame::io::WriteFrame;

    #[test]
    fn test_read_new_token_frame() {
        use super::be_new_token_frame;
        let buf = vec![0x02, 0x01, 0x02];
        let (input, frame) = be_new_token_frame(&buf).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(frame.token, vec![0x01, 0x02]);
    }

    #[test]
    fn test_write_new_token_frame() {
        let mut buf = Vec::<u8>::new();
        let frame = super::NewTokenFrame {
            token: vec![0x01, 0x02],
        };
        buf.put_frame(&frame);
        assert_eq!(buf, vec![0x07, 0x02, 0x01, 0x02]);
    }
}
