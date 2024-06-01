// PATH_CHALLENGE Frame {
//   Type (i) = 0x1a,
//   Data (64),
// }

use crate::packet::r#type::Type;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathChallengeFrame {
    pub data: [u8; 8],
}

impl PathChallengeFrame {
    pub fn from_slice(data: &[u8]) -> Self {
        let mut frame = Self { data: [0; 8] };
        frame.data.copy_from_slice(data);
        frame
    }

    pub fn random_gen() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut data = [0; 8];
        rng.fill(&mut data);
        Self { data }
    }

    pub fn response(&self) -> super::PathResponseFrame {
        super::PathResponseFrame::from_slice(&self.data[..])
    }
}

const PATH_CHALLENGE_FRAME_TYPE: u8 = 0x1a;

impl super::BeFrame for PathChallengeFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PathChallenge
    }

    fn belongs_to(&self, packet_type: Type) -> bool {
        use crate::packet::r#type::{
            long::{Type::V1, Ver1},
            short::OneRtt,
        };
        // __01
        matches!(
            packet_type,
            Type::Long(V1(Ver1::ZERO_RTT)) | Type::Short(OneRtt(_))
        )
    }

    fn max_encoding_size(&self) -> usize {
        1 + self.data.len()
    }

    fn encoding_size(&self) -> usize {
        1 + self.data.len()
    }
}

// nom parser for PATH_CHALLENGE_FRAME
pub fn be_path_challenge_frame(input: &[u8]) -> nom::IResult<&[u8], PathChallengeFrame> {
    use nom::bytes::streaming::take;
    use nom::combinator::map;
    map(take(8usize), PathChallengeFrame::from_slice)(input)
}

// BufMut write extension for PATH_CHALLENGE_FRAME
pub trait WritePathChallengeFrame {
    fn put_path_challenge_frame(&mut self, frame: &PathChallengeFrame);
}

impl<T: bytes::BufMut> WritePathChallengeFrame for T {
    fn put_path_challenge_frame(&mut self, frame: &PathChallengeFrame) {
        self.put_u8(PATH_CHALLENGE_FRAME_TYPE);
        self.put_slice(&frame.data);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_read_path_challenge_frame() {
        use super::be_path_challenge_frame;
        use crate::varint::be_varint;
        use nom::combinator::flat_map;
        let buf = vec![
            super::PATH_CHALLENGE_FRAME_TYPE,
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
            if frame_type.into_inner() == super::PATH_CHALLENGE_FRAME_TYPE as u64 {
                be_path_challenge_frame
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[][..]);
        assert_eq!(
            frame,
            super::PathChallengeFrame {
                data: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
            }
        );
    }

    #[test]
    fn test_write_path_challenge_frame() {
        use super::WritePathChallengeFrame;
        let mut buf = Vec::new();
        let frame = super::PathChallengeFrame {
            data: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        };
        buf.put_path_challenge_frame(&frame);
        assert_eq!(
            buf,
            vec![
                super::PATH_CHALLENGE_FRAME_TYPE,
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
