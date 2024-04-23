// MAX_DATA Frame {
//   Type (i) = 0x10,
//   Maximum Data (i),
// }

use crate::varint::VarInt;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaxDataFrame {
    pub max_data: VarInt,
}

pub(super) const MAX_DATA_FRAME_TYPE: u8 = 0x10;

pub(super) mod ext {
    use super::MaxDataFrame;

    // nom parser for MAX_DATA_FRAME
    pub fn be_max_data_frame(input: &[u8]) -> nom::IResult<&[u8], MaxDataFrame> {
        let (input, max_data) = crate::varint::ext::be_varint(input)?;
        Ok((input, MaxDataFrame { max_data }))
    }

    // BufMut write extension for MAX_DATA_FRAME
    pub trait BufMutExt {
        fn put_max_data_frame(&mut self, frame: &MaxDataFrame);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_max_data_frame(&mut self, frame: &MaxDataFrame) {
            use crate::varint::ext::BufMutExt as VarIntBufMutExt;
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
        use super::ext::BufMutExt;

        let mut buf = Vec::new();
        buf.put_max_data_frame(&MaxDataFrame {
            max_data: VarInt(0x1234),
        });
        assert_eq!(buf, vec![MAX_DATA_FRAME_TYPE, 0x52, 0x34]);
    }
}
