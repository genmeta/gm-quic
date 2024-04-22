// MAX_STREAM_DATA Frame {
//   Type (i) = 0x11,
//   Stream ID (i),
//   Maximum Stream Data (i),
// }

use crate::{streamid::StreamId, varint::VarInt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxStreamDataFrame {
    pub stream_id: StreamId,
    pub max_stream_data: VarInt,
}

pub(super) const MAX_STREAM_DATA_FRAME_TYPE: u8 = 0x11;

pub(super) mod ext {
    use super::{MaxStreamDataFrame, MAX_STREAM_DATA_FRAME_TYPE};

    // nom parser for MAX_STREAM_DATA_FRAME
    pub fn be_max_stream_data_frame(input: &[u8]) -> nom::IResult<&[u8], MaxStreamDataFrame> {
        use crate::{streamid::ext::be_streamid, varint::ext::be_varint};
        let (input, stream_id) = be_streamid(input)?;
        let (input, max_stream_data) = be_varint(input)?;
        Ok((
            input,
            MaxStreamDataFrame {
                stream_id,
                max_stream_data,
            },
        ))
    }

    // BufMut write extension for MAX_STREAM_DATA_FRAME
    pub trait BufMutExt {
        fn put_max_stream_data_frame(&mut self, frame: &MaxStreamDataFrame);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_max_stream_data_frame(&mut self, frame: &MaxStreamDataFrame) {
            use crate::streamid::ext::BufMutExt as StreamIdBufMutExt;
            use crate::varint::ext::BufMutExt as VarIntBufMutExt;
            self.put_u8(MAX_STREAM_DATA_FRAME_TYPE);
            self.put_streamid(&frame.stream_id);
            self.put_varint(&frame.max_stream_data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MaxStreamDataFrame, MAX_STREAM_DATA_FRAME_TYPE};
    use crate::varint::VarInt;

    #[test]
    fn test_read_max_stream_data_frame() {
        use super::ext::be_max_stream_data_frame;
        let buf = vec![0x52, 0x34, 0x80, 0, 0x56, 0x78];
        let (_, frame) = be_max_stream_data_frame(&buf).unwrap();
        assert_eq!(frame.stream_id, VarInt::from_u32(0x1234).into());
        assert_eq!(frame.max_stream_data, VarInt::from_u32(0x5678));
    }

    #[test]
    fn test_write_max_stream_data_frame() {
        use super::ext::BufMutExt;
        let mut buf = Vec::new();
        buf.put_max_stream_data_frame(&MaxStreamDataFrame {
            stream_id: VarInt::from_u32(0x1234).into(),
            max_stream_data: VarInt::from_u32(0x5678),
        });
        assert_eq!(
            buf,
            vec![MAX_STREAM_DATA_FRAME_TYPE, 0x52, 0x34, 0x80, 0, 0x56, 0x78]
        );
    }
}
