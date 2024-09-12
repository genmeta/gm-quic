use crate::varint::{be_varint, VarInt, WriteVarInt};

/// MAX_DATA Frame
///
/// ```text
/// MAX_DATA Frame {
///   Type (i) = 0x10,
///   Maximum Data (i),
/// }
/// ```
///
/// See [MAX_DATA Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-max_data-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaxDataFrame {
    pub max_data: VarInt,
}

const MAX_DATA_FRAME_TYPE: u8 = 0x10;

impl super::BeFrame for MaxDataFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::MaxData
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.max_data.encoding_size()
    }
}

/// Parse a MAX_DATA frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_max_data_frame(input: &[u8]) -> nom::IResult<&[u8], MaxDataFrame> {
    use nom::combinator::map;
    map(be_varint, |max_data| MaxDataFrame { max_data })(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<MaxDataFrame> for T {
    fn put_frame(&mut self, frame: &MaxDataFrame) {
        self.put_u8(MAX_DATA_FRAME_TYPE);
        self.put_varint(&frame.max_data);
    }
}

#[cfg(test)]
mod tests {
    use super::{MaxDataFrame, MAX_DATA_FRAME_TYPE};
    use crate::{frame::io::WriteFrame, varint::VarInt};

    #[test]
    fn test_read_max_data_frame() {
        use nom::combinator::flat_map;

        use super::be_max_data_frame;
        use crate::varint::be_varint;
        let buf = vec![MAX_DATA_FRAME_TYPE, 0x52, 0x34];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == MAX_DATA_FRAME_TYPE as u64 {
                be_max_data_frame
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(
            frame,
            MaxDataFrame {
                max_data: VarInt::from_u32(0x1234),
            }
        );
    }

    #[test]
    fn test_write_max_data_frame() {
        let mut buf = Vec::new();
        buf.put_frame(&MaxDataFrame {
            max_data: VarInt::from_u32(0x1234),
        });
        assert_eq!(buf, vec![MAX_DATA_FRAME_TYPE, 0x52, 0x34]);
    }
}
