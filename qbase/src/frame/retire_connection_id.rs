// RETIRE_CONNECTION_ID Frame {
//   Type (i) = 0x19,
//   Sequence Number (i),
// }

use crate::varint::VarInt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireConnectionIdFrame {
    pub sequence: VarInt,
}

pub(super) const RETIRE_CONNECTION_ID_FRAME_TYPE: u8 = 0x19;

impl super::BeFrame for RetireConnectionIdFrame {
    fn frame_type(&self) -> VarInt {
        VarInt::from(RETIRE_CONNECTION_ID_FRAME_TYPE)
    }
}

pub(super) mod ext {
    use super::{RetireConnectionIdFrame, RETIRE_CONNECTION_ID_FRAME_TYPE};
    use crate::varint::ext::be_varint;
    use nom::combinator::map;

    // nom parser for RETIRE_CONNECTION_ID_FRAME
    pub fn be_retire_connection_id_frame(
        input: &[u8],
    ) -> nom::IResult<&[u8], RetireConnectionIdFrame> {
        map(be_varint, |sequence| RetireConnectionIdFrame { sequence })(input)
    }

    // BufMut extension trait for RETIRE_CONNECTION_ID_FRAME
    pub trait BufMutExt {
        fn put_retire_connection_id_frame(&mut self, frame: &RetireConnectionIdFrame);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_retire_connection_id_frame(&mut self, frame: &RetireConnectionIdFrame) {
            use crate::varint::ext::BufMutExt as VarIntBufMutExt;
            self.put_u8(RETIRE_CONNECTION_ID_FRAME_TYPE);
            self.put_varint(&frame.sequence);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ext::be_retire_connection_id_frame, RetireConnectionIdFrame};
    use crate::varint::VarInt;

    #[test]
    fn test_read_retire_connection_id_frame() {
        let buf = vec![0x52, 0x34];
        let (remain, frame) = be_retire_connection_id_frame(&buf).unwrap();
        assert_eq!(remain, &[]);
        assert_eq!(
            frame,
            RetireConnectionIdFrame {
                sequence: VarInt(0x1234),
            }
        );
    }

    #[test]
    fn test_write_retire_connection_id_frame() {
        use super::ext::BufMutExt;
        let mut buf = Vec::new();
        let frame = RetireConnectionIdFrame {
            sequence: VarInt(0x1234),
        };
        buf.put_retire_connection_id_frame(&frame);
        assert_eq!(buf, vec![0x19, 0x52, 0x34]);
    }
}
