// MAX_DATA Frame {
//   Type (i) = 0x10,
//   Maximum Data (i),
// }

use crate::{varint::VarInt, SpaceId};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaxDataFrame {
    pub max_data: VarInt,
}

const MAX_DATA_FRAME_TYPE: u8 = 0x10;

impl super::BeFrame for MaxDataFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::MaxData
    }

    fn belongs_to(&self, space_id: SpaceId) -> bool {
        // __01
        space_id == SpaceId::ZeroRtt || space_id == SpaceId::OneRtt
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.max_data.encoding_size()
    }
}

pub(super) mod ext {
    use super::MaxDataFrame;

    // nom parser for MAX_DATA_FRAME
    pub fn be_max_data_frame(input: &[u8]) -> nom::IResult<&[u8], MaxDataFrame> {
        use crate::varint::ext::be_varint;
        use nom::combinator::map;
        map(be_varint, |max_data| MaxDataFrame { max_data })(input)
    }

    // BufMut write extension for MAX_DATA_FRAME
    pub trait WriteMaxDataFrame {
        fn put_max_data_frame(&mut self, frame: &MaxDataFrame);
    }

    impl<T: bytes::BufMut> WriteMaxDataFrame for T {
        fn put_max_data_frame(&mut self, frame: &MaxDataFrame) {
            use crate::varint::ext::WriteVarInt;
            self.put_u8(super::MAX_DATA_FRAME_TYPE);
            self.put_varint(&frame.max_data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MaxDataFrame, MAX_DATA_FRAME_TYPE};
    use crate::varint::VarInt;

    #[test]
    fn test_read_max_data_frame() {
        use super::ext::be_max_data_frame;
        use crate::varint::ext::be_varint;
        use nom::combinator::flat_map;
        let buf = vec![MAX_DATA_FRAME_TYPE, 0x52, 0x34];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == MAX_DATA_FRAME_TYPE as u64 {
                be_max_data_frame
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[][..]);
        assert_eq!(
            frame,
            MaxDataFrame {
                max_data: VarInt(0x1234),
            }
        );
    }

    #[test]
    fn test_write_max_data_frame() {
        use super::ext::WriteMaxDataFrame;

        let mut buf = Vec::new();
        buf.put_max_data_frame(&MaxDataFrame {
            max_data: VarInt(0x1234),
        });
        assert_eq!(buf, vec![MAX_DATA_FRAME_TYPE, 0x52, 0x34]);
    }
}
