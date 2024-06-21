// RETIRE_CONNECTION_ID Frame {
//   Type (i) = 0x19,
//   Sequence Number (i),
// }

use crate::{
    packet::r#type::Type,
    varint::{be_varint, VarInt, WriteVarInt},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireConnectionIdFrame {
    pub sequence: VarInt,
}

const RETIRE_CONNECTION_ID_FRAME_TYPE: u8 = 0x19;

impl super::BeFrame for RetireConnectionIdFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::RetireConnectionId
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
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.sequence.encoding_size()
    }
}

// nom parser for RETIRE_CONNECTION_ID_FRAME
pub fn be_retire_connection_id_frame(input: &[u8]) -> nom::IResult<&[u8], RetireConnectionIdFrame> {
    use nom::combinator::map;
    map(be_varint, |sequence| RetireConnectionIdFrame { sequence })(input)
}

// BufMut extension trait for RETIRE_CONNECTION_ID_FRAME
pub trait WriteRetireConnectionIdFrame {
    fn put_retire_connection_id_frame(&mut self, frame: &RetireConnectionIdFrame);
}

impl<T: bytes::BufMut> WriteRetireConnectionIdFrame for T {
    fn put_retire_connection_id_frame(&mut self, frame: &RetireConnectionIdFrame) {
        self.put_u8(RETIRE_CONNECTION_ID_FRAME_TYPE);
        self.put_varint(&frame.sequence);
    }
}

#[cfg(test)]
mod tests {
    use super::{be_retire_connection_id_frame, RetireConnectionIdFrame};
    use crate::varint::VarInt;

    #[test]
    fn test_read_retire_connection_id_frame() {
        let buf = vec![0x52, 0x34];
        let (remain, frame) = be_retire_connection_id_frame(&buf).unwrap();
        assert_eq!(remain, &[]);
        assert_eq!(
            frame,
            RetireConnectionIdFrame {
                sequence: VarInt::from_u32(0x1234),
            }
        );
    }

    #[test]
    fn test_write_retire_connection_id_frame() {
        use super::WriteRetireConnectionIdFrame;
        let mut buf = Vec::new();
        let frame = RetireConnectionIdFrame {
            sequence: VarInt::from_u32(0x1234),
        };
        buf.put_retire_connection_id_frame(&frame);
        assert_eq!(buf, vec![0x19, 0x52, 0x34]);
    }
}
