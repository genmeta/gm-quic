use derive_more::Deref;
use qbase::{
    frame::EncodeSize,
    net::route::{WriteLink, be_link},
    varint::{VarInt, WriteVarInt},
};

use super::{FrameType, GetFrameType, io};
use crate::{
    Link,
    frame::{KONCK_FRAME_TYPE, PunchPair},
};

/// KONCK Frame {
///     Type (i) = 0x3d7e95,
///     Link,
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deref)]
pub struct KonckFrame {
    #[deref]
    punch_pair: Link,
}

impl KonckFrame {
    pub fn new(link: Link) -> Self {
        Self { punch_pair: link }
    }
}

impl PunchPair for KonckFrame {
    fn punch_pair(&self) -> Option<Link> {
        Some(self.punch_pair)
    }
}

pub fn be_konck_frame(input: &[u8]) -> nom::IResult<&[u8], KonckFrame> {
    let (input, link) = be_link(input)?;
    Ok((input, KonckFrame { punch_pair: link }))
}

impl GetFrameType for KonckFrame {
    fn frame_type(&self) -> FrameType {
        FrameType::Konck
    }
}

impl EncodeSize for KonckFrame {
    fn max_encoding_size(&self) -> usize {
        VarInt::from_u32(KONCK_FRAME_TYPE).encoding_size() + self.punch_pair.max_encoding_size()
    }

    fn encoding_size(&self) -> usize {
        VarInt::from_u32(KONCK_FRAME_TYPE).encoding_size() + self.punch_pair.encoding_size()
    }
}

impl<T: bytes::BufMut> io::WriteFrame<KonckFrame> for T {
    fn put_frame(&mut self, frame: &KonckFrame) {
        self.put_varint(&VarInt::from_u32(KONCK_FRAME_TYPE));
        self.put_link(&frame.punch_pair);
    }
}
