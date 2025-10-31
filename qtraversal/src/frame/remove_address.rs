use derive_more::Deref;
use qbase::{
    frame::EncodeSize,
    varint::{VarInt, WriteVarInt, be_varint},
};

use super::{FrameType, GetFrameType, io};
use crate::{
    Link,
    frame::{PunchPair, REMOVE_ADDRESS_FRAME_TYPE},
};

/// REMOVE_ADDRESS Frame {
///     Type (i) = 0x3d7e94,
///     Sequence Number (i),
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deref)]
pub struct RemoveAddressFrame {
    #[deref]
    pub seq_num: VarInt,
}

impl PunchPair for RemoveAddressFrame {
    fn punch_pair(&self) -> Option<Link> {
        None
    }
}

pub fn be_remove_address_frame(input: &[u8]) -> nom::IResult<&[u8], RemoveAddressFrame> {
    let (input, sequence_number) = be_varint(input)?;
    Ok((
        input,
        RemoveAddressFrame {
            seq_num: sequence_number,
        },
    ))
}

impl GetFrameType for RemoveAddressFrame {
    fn frame_type(&self) -> FrameType {
        FrameType::RemoveAddress
    }
}

impl EncodeSize for RemoveAddressFrame {
    fn max_encoding_size(&self) -> usize {
        VarInt::from_u32(REMOVE_ADDRESS_FRAME_TYPE).encoding_size() + self.seq_num.encoding_size()
    }

    fn encoding_size(&self) -> usize {
        VarInt::from_u32(REMOVE_ADDRESS_FRAME_TYPE).encoding_size() + self.seq_num.encoding_size()
    }
}

impl<T: bytes::BufMut> io::WriteFrame<RemoveAddressFrame> for T {
    fn put_frame(&mut self, frame: &RemoveAddressFrame) {
        self.put_varint(&VarInt::from_u32(REMOVE_ADDRESS_FRAME_TYPE));
        self.put_varint(&frame.seq_num);
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::frame::io::WriteFrame;

    #[test]
    fn test_remove_address_frame() {
        let frame = RemoveAddressFrame {
            seq_num: VarInt::from_u32(0x1234),
        };

        assert_eq!(frame.max_encoding_size(), 6);
        assert_eq!(frame.encoding_size(), 6);

        let mut buf = BytesMut::new();
        buf.put_frame(&frame);

        let (remain, typ) = be_varint(&buf).unwrap();
        assert_eq!(typ, VarInt::from_u32(REMOVE_ADDRESS_FRAME_TYPE));
        let frame2 = be_remove_address_frame(remain).unwrap().1;
        assert_eq!(frame, frame2);
    }
}
