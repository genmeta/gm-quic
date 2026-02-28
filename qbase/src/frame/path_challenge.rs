use derive_more::Deref;

use crate::frame::{GetFrameType, io::WriteFrameType};
/// PATH_CHALLENGE frame.
///
/// ```text
/// PATH_CHALLENGE Frame {
///   Type (i) = 0x1a,
///   Data (64),
/// }
/// ```
///
/// See [PATH_CHALLENGE Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-path_challenge-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
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
        let mut rng = rand::rng();
        let mut data = [0; 8];
        rng.fill(&mut data);
        Self { data }
    }
}

impl super::GetFrameType for PathChallengeFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PathChallenge
    }
}

impl super::EncodeSize for PathChallengeFrame {
    fn max_encoding_size(&self) -> usize {
        1 + self.data.len()
    }

    fn encoding_size(&self) -> usize {
        1 + self.data.len()
    }
}

/// Parse a PATH_CHALLENGE frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_path_challenge_frame(input: &[u8]) -> nom::IResult<&[u8], PathChallengeFrame> {
    use nom::{Parser, bytes::streaming::take, combinator::map};
    map(take(8usize), PathChallengeFrame::from_slice).parse(input)
}

// BufMut write extension for PATH_CHALLENGE_FRAME
impl<T: bytes::BufMut> super::io::WriteFrame<PathChallengeFrame> for T {
    fn put_frame(&mut self, frame: &PathChallengeFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_slice(&frame.data);
    }
}

#[cfg(test)]
mod tests {
    use nom::{Parser, combinator::flat_map};

    use super::be_path_challenge_frame;
    use crate::{
        frame::{
            EncodeSize, FrameType, GetFrameType,
            io::{WriteFrame, WriteFrameType},
        },
        varint::{VarInt, be_varint},
    };
    #[test]
    fn test_path_challenge_frame() {
        let frame = super::PathChallengeFrame::from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ]);
        assert_eq!(frame.frame_type(), FrameType::PathChallenge);
        assert_eq!(frame.max_encoding_size(), 1 + 8);
        assert_eq!(frame.encoding_size(), 1 + 8);
    }

    #[test]
    fn test_read_path_challenge_frame() {
        let path_challenge_frame_type = VarInt::from(FrameType::PathChallenge);
        let mut buf = Vec::new();
        buf.put_frame_type(FrameType::PathChallenge);
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type == path_challenge_frame_type {
                be_path_challenge_frame
            } else {
                panic!("wrong frame type: {frame_type}")
            }
        })
        .parse(buf.as_ref())
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
        let mut buf = Vec::new();
        let frame = super::PathChallengeFrame::from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ]);
        buf.put_frame(&frame);
        let mut expected = Vec::new();
        expected.put_frame_type(FrameType::PathChallenge);
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(buf, expected);
    }
}
