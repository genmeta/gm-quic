// PATH_CHALLENGE Frame {
//   Type (i) = 0x1a,
//   Data (64),
// }

use deref_derive::Deref;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deref)]
pub struct PathChallengeFrame {
    #[deref]
    data: [u8; 8],
}

impl PathChallengeFrame {
    pub fn from_slice(data: &[u8]) -> Self {
        let mut frame = Self { data: [0; 8] };
        frame.data.copy_from_slice(data);
        frame
    }

    pub fn random() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut data = [0; 8];
        rng.fill(&mut data);
        Self { data }
    }
}

const PATH_CHALLENGE_FRAME_TYPE: u8 = 0x1a;

impl super::BeFrame for PathChallengeFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PathChallenge
    }

    fn max_encoding_size(&self) -> usize {
        1 + self.data.len()
    }

    fn encoding_size(&self) -> usize {
        1 + self.data.len()
    }
}

pub fn be_path_challenge_frame(input: &[u8]) -> nom::IResult<&[u8], PathChallengeFrame> {
    use nom::{bytes::streaming::take, combinator::map};
    map(take(8usize), PathChallengeFrame::from_slice)(input)
}

// BufMut write extension for PATH_CHALLENGE_FRAME
impl<T: bytes::BufMut> super::io::WriteFrame<PathChallengeFrame> for T {
    fn put_frame(&mut self, frame: &PathChallengeFrame) {
        self.put_u8(PATH_CHALLENGE_FRAME_TYPE);
        self.put_slice(&frame.data);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_read_path_challenge_frame() {
        use nom::combinator::flat_map;

        use super::be_path_challenge_frame;
        use crate::varint::be_varint;
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
        assert!(input.is_empty());
        assert_eq!(
            frame,
            super::PathChallengeFrame {
                data: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
            }
        );
    }

    #[test]
    fn test_write_path_challenge_frame() {
        use crate::frame::io::WriteFrame;
        let mut buf = Vec::new();
        let frame = super::PathChallengeFrame {
            data: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        };
        buf.put_frame(&frame);
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
