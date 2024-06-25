// RESET_STREAM Frame {
//   Type (i) = 0x04,
//   Stream ID (i),
//   Application Protocol Error Code (i),
//   Final Size (i),
// }

use crate::{
    packet::r#type::Type,
    streamid::{be_streamid, StreamId, WriteStreamId},
    varint::{be_varint, VarInt, WriteVarInt},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetStreamFrame {
    pub stream_id: StreamId,
    pub app_error_code: VarInt,
    pub final_size: VarInt,
}

const RESET_STREAM_FRAME_TYPE: u8 = 0x04;

impl super::BeFrame for ResetStreamFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::ResetStream
    }

    fn belongs_to(&self, packet_type: Type) -> bool {
        use crate::packet::r#type::{
            long::{Type::V1, Ver1},
            short::OneRtt,
        };
        // __01
        matches!(
            packet_type,
            Type::Long(V1(Ver1::ZERO_RTT)) | Type::Short(OneRtt(_))
        )
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size()
            + self.app_error_code.encoding_size()
            + self.final_size.encoding_size()
    }
}

// nom parser for RESET_STREAM_FRAME
pub fn be_reset_stream_frame(input: &[u8]) -> nom::IResult<&[u8], ResetStreamFrame> {
    use nom::{combinator::map, sequence::tuple};
    map(
        tuple((be_streamid, be_varint, be_varint)),
        |(stream_id, app_error_code, final_size)| ResetStreamFrame {
            stream_id,
            app_error_code,
            final_size,
        },
    )(input)
}

// BufMut write extension for RESET_STREAM_FRAME
pub trait WriteResetStreamFrame {
    fn put_reset_stream_frame(&mut self, frame: &ResetStreamFrame);
}

impl<T: bytes::BufMut> WriteResetStreamFrame for T {
    fn put_reset_stream_frame(&mut self, frame: &ResetStreamFrame) {
        self.put_u8(RESET_STREAM_FRAME_TYPE);
        self.put_streamid(&frame.stream_id);
        self.put_varint(&frame.app_error_code);
        self.put_varint(&frame.final_size);
    }
}

#[cfg(test)]
mod tests {
    use nom::combinator::flat_map;

    use super::{ResetStreamFrame, WriteResetStreamFrame, RESET_STREAM_FRAME_TYPE};
    use crate::varint::{be_varint, VarInt};

    #[test]
    fn test_read_reset_stream_frame() {
        let buf = vec![
            RESET_STREAM_FRAME_TYPE,
            0x52,
            0x34,
            0x80,
            0,
            0x56,
            0x78,
            0x80,
            0,
            0x9a,
            0xbc,
        ];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == RESET_STREAM_FRAME_TYPE as u64 {
                super::be_reset_stream_frame
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[][..]);
        assert_eq!(
            frame,
            ResetStreamFrame {
                stream_id: VarInt::from_u32(0x1234).into(),
                app_error_code: VarInt::from_u32(0x5678),
                final_size: VarInt::from_u32(0x9abc),
            }
        );
    }

    #[test]
    fn test_write_reset_stream_frame() {
        let mut buf = Vec::new();
        buf.put_reset_stream_frame(&ResetStreamFrame {
            stream_id: VarInt::from_u32(0x1234).into(),
            // 0x5678 = 0b01010110 01111000 => 0b10000000 0x00 0x56 0x78
            app_error_code: VarInt::from_u32(0x5678),
            // 0x9abc = 0b10011010 10111100 => 0b10000000 0x00 0x9a 0xbc
            final_size: VarInt::from_u32(0x9abc),
        });
        assert_eq!(
            buf,
            vec![
                RESET_STREAM_FRAME_TYPE,
                0x52,
                0x34,
                0x80,
                0,
                0x56,
                0x78,
                0x80,
                0,
                0x9a,
                0xbc
            ]
        );
    }
}
