use std::ops::Deref;

use derive_more::Deref;

/// PATH_RESPONSE Frame.
///
/// ```text
/// PATH_RESPONSE Frame {
///   Type (i) = 0x1b,
///   Data (64),
/// }
/// ```
///
/// See [PATH_RESPONSE Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-path_response-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
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
impl From<super::PathChallengeFrame> for PathResponseFrame {
    fn from(challenge: super::PathChallengeFrame) -> Self {
        Self::from_slice(challenge.deref())
    }
}

const PATH_RESPONSE_FRAME_TYPE: u8 = 0x1b;

impl super::GetFrameType for PathResponseFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PathResponse
    }
}

impl super::EncodeFrame for PathResponseFrame {
    fn max_encoding_size(&self) -> usize {
        1 + self.data.len()
    }

    fn encoding_size(&self) -> usize {
        1 + self.data.len()
    }
}

/// Parse a PATH_RESPONSE frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_path_response_frame(input: &[u8]) -> nom::IResult<&[u8], PathResponseFrame> {
    use nom::{Parser, bytes::complete::take, combinator::map};
    map(take(8usize), PathResponseFrame::from_slice).parse(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<PathResponseFrame> for T {
    fn put_frame(&mut self, frame: &PathResponseFrame) {
        self.put_u8(PATH_RESPONSE_FRAME_TYPE);
        self.put_slice(&frame.data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{EncodeFrame, FrameType, GetFrameType, io::WriteFrame};

    #[test]
    fn test_path_response_frame() {
        let frame =
            PathResponseFrame::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(frame.frame_type(), FrameType::PathResponse);
        assert_eq!(frame.max_encoding_size(), 1 + 8);
        assert_eq!(frame.encoding_size(), 1 + 8);
    }

    #[test]
    fn test_read_path_response_frame() {
        use nom::{Parser, combinator::flat_map};

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
                panic!("wrong frame type: {frame_type}")
            }
        })
        .parse(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(
            frame,
            PathResponseFrame::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        );
    }

    #[test]
    fn test_write_path_response_frame() {
        let mut buf = Vec::<u8>::new();
        let frame =
            PathResponseFrame::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        buf.put_frame(&frame);
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
