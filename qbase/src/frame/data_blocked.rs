use crate::varint::{be_varint, VarInt, WriteVarInt};

/// DATA_BLOCKED Frame
///
/// ```text
/// DATA_BLOCKED Frame {
///   Type (i) = 0x14,
///   Maximum Data (i),
/// }
/// ```
///
/// See [data-blocked frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-data_blocked-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DataBlockedFrame {
    pub limit: VarInt,
}

const DATA_BLOCKED_FRAME_TYPE: u8 = 0x14;

impl super::BeFrame for DataBlockedFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Crypto
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.limit.encoding_size()
    }
}

/// Parse a DATA_BLOCKED frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_data_blocked_frame(input: &[u8]) -> nom::IResult<&[u8], DataBlockedFrame> {
    use nom::combinator::map;
    map(be_varint, |limit| DataBlockedFrame { limit })(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<DataBlockedFrame> for T {
    fn put_frame(&mut self, frame: &DataBlockedFrame) {
        self.put_u8(DATA_BLOCKED_FRAME_TYPE);
        self.put_varint(&frame.limit);
    }
}

#[cfg(test)]
mod tests {
    use super::{DataBlockedFrame, DATA_BLOCKED_FRAME_TYPE};
    use crate::frame::{io::WriteFrame, BeFrame};

    #[test]
    fn test_data_blocked_frame() {
        let frame = DataBlockedFrame {
            limit: crate::varint::VarInt::from_u32(0x1234),
        };
        assert_eq!(frame.frame_type(), super::super::FrameType::Crypto);
        assert_eq!(frame.max_encoding_size(), 1 + 8);
        assert_eq!(frame.encoding_size(), 1 + 2);
    }

    #[test]
    fn test_read_data_blocked_frame() {
        use super::be_data_blocked_frame;
        let buf = vec![0x52, 0x34];
        let (_, frame) = be_data_blocked_frame(&buf).unwrap();
        assert_eq!(
            frame,
            DataBlockedFrame {
                limit: crate::varint::VarInt::from_u32(0x1234)
            }
        );
    }

    #[test]
    fn test_write_data_blocked_frame() {
        let mut buf = Vec::new();
        buf.put_frame(&DataBlockedFrame {
            limit: crate::varint::VarInt::from_u32(0x1234),
        });
        assert_eq!(buf, vec![DATA_BLOCKED_FRAME_TYPE, 0x52, 0x34]);
    }
}
