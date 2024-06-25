// PATH_RESPONSE Frame {
//   Type (i) = 0x1b,
//   Data (64),
// }

use std::ops::Deref;

use deref_derive::Deref;

use crate::packet::r#type::Type;

#[derive(Debug, Clone, Copy, Default, Deref, PartialEq, Eq)]
pub struct PathResponseFrame {
    #[deref]
    data: [u8; 8],
}

impl PathResponseFrame {
    fn from_slice(data: &[u8]) -> Self {
        let mut frame = Self { data: [0; 8] };
        frame.data.copy_from_slice(data);
        frame
    }
}

/// The only public way to create a PathResponseFrame is from a PathChallengeFrame
impl From<&super::PathChallengeFrame> for PathResponseFrame {
    fn from(challenge: &super::PathChallengeFrame) -> Self {
        Self::from_slice(challenge.deref())
    }
}

const PATH_RESPONSE_FRAME_TYPE: u8 = 0x1b;

impl super::BeFrame for PathResponseFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PathResponse
    }

    fn belongs_to(&self, packet_type: Type) -> bool {
        use crate::packet::r#type::short::OneRtt;
        // ___1
        matches!(packet_type, Type::Short(OneRtt(_)))
    }

    fn max_encoding_size(&self) -> usize {
        1 + self.data.len()
    }

    fn encoding_size(&self) -> usize {
        1 + self.data.len()
    }
}

// nom parser for PATH_RESPONSE_FRAME
pub fn be_path_response_frame(input: &[u8]) -> nom::IResult<&[u8], PathResponseFrame> {
    use nom::{bytes::complete::take, combinator::map};
    map(take(8usize), PathResponseFrame::from_slice)(input)
}

// BufMut write extension for PATH_RESPONSE_FRAME
pub trait WritePathResponseFrame {
    fn put_path_response_frame(&mut self, frame: &PathResponseFrame);
}

impl<T: bytes::BufMut> WritePathResponseFrame for T {
    fn put_path_response_frame(&mut self, frame: &PathResponseFrame) {
        self.put_u8(PATH_RESPONSE_FRAME_TYPE);
        self.put_slice(&frame.data);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_read_path_response_frame() {
        use nom::combinator::flat_map;

        use super::be_path_response_frame;
        use crate::varint::be_varint;
        let buf = vec![
            super::PATH_RESPONSE_FRAME_TYPE,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
        ];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == super::PATH_RESPONSE_FRAME_TYPE as u64 {
                be_path_response_frame
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[][..]);
        assert_eq!(
            frame,
            super::PathResponseFrame {
                data: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
            }
        );
    }

    #[test]
    fn test_write_path_response_frame() {
        use super::WritePathResponseFrame;
        let mut buf = Vec::<u8>::new();
        let frame = super::PathResponseFrame {
            data: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        };
        buf.put_path_response_frame(&frame);
        assert_eq!(
            buf,
            vec![
                super::PATH_RESPONSE_FRAME_TYPE,
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08
            ]
        );
    }
}
