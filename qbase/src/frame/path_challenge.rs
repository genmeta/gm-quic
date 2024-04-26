// PATH_CHALLENGE Frame {
//   Type (i) = 0x1a,
//   Data (64),
// }

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathChallengeFrame {
    pub data: [u8; 8],
}

pub(super) const PATH_CHALLENGE_FRAME_TYPE: u8 = 0x1a;

pub(super) mod ext {
    use super::PathChallengeFrame;

    // nom parser for PATH_CHALLENGE_FRAME
    pub fn be_path_challenge_frame(input: &[u8]) -> nom::IResult<&[u8], PathChallengeFrame> {
        use nom::bytes::complete::take;
        use nom::combinator::map;
        map(take(8usize), |data: &[u8]| {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(data);
            PathChallengeFrame { data: buf }
        })(input)
    }

    // BufMut write extension for PATH_CHALLENGE_FRAME
    pub trait BufMutExt {
        fn put_path_challenge_frame(&mut self, frame: &PathChallengeFrame);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_path_challenge_frame(&mut self, frame: &PathChallengeFrame) {
            self.put_u8(super::PATH_CHALLENGE_FRAME_TYPE);
            self.put_slice(&frame.data);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_read_path_challenge_frame() {
        use super::ext::be_path_challenge_frame;
        use crate::varint::ext::be_varint;
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
        use super::ext::BufMutExt;
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
