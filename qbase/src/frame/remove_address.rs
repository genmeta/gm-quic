use derive_more::Deref;

use super::{
    EncodeSize, GetFrameType,
    io::{WriteFrame, WriteFrameType},
};
use crate::varint::{VarInt, WriteVarInt, be_varint};

/// REMOVE_ADDRESS Frame {
///     Type (i) = 0x3d7e94,
///     Sequence Number (i),
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deref)]
pub struct RemoveAddressFrame {
    #[deref]
    pub seq_num: VarInt,
}

pub(crate) fn be_remove_address_frame(input: &[u8]) -> nom::IResult<&[u8], RemoveAddressFrame> {
    let (input, sequence_number) = be_varint(input)?;
    Ok((
        input,
        RemoveAddressFrame {
            seq_num: sequence_number,
        },
    ))
}

impl GetFrameType for RemoveAddressFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::RemoveAddress
    }
}

impl EncodeSize for RemoveAddressFrame {
    fn max_encoding_size(&self) -> usize {
        4 + 8
    }

    fn encoding_size(&self) -> usize {
        VarInt::from(self.frame_type()).encoding_size() + self.seq_num.encoding_size()
    }
}

impl<T: bytes::BufMut> WriteFrame<RemoveAddressFrame> for T {
    fn put_frame(&mut self, frame: &RemoveAddressFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_varint(&frame.seq_num);
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::frame::{GetFrameType, be_frame_type, io::WriteFrame};

    #[test]
    fn test_remove_address_frame() {
        let frame = RemoveAddressFrame {
            seq_num: VarInt::from_u32(0x1234),
        };

        assert_eq!(frame.max_encoding_size(), 12);
        assert_eq!(frame.encoding_size(), 6);

        let mut buf = BytesMut::new();
        buf.put_frame(&frame);

        let (remain, frame_type) = be_frame_type(&buf).unwrap();
        assert_eq!(frame_type, frame.frame_type());
        let frame2 = be_remove_address_frame(remain).unwrap().1;
        assert_eq!(frame, frame2);
    }
}
