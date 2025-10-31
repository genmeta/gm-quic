use derive_more::Deref;
use qbase::{
    frame::EncodeSize,
    net::route::{WriteLink, be_link},
    varint::{VarInt, WriteVarInt},
};

use super::{FrameType, GetFrameType, io};
use crate::frame::{Link, PUNCH_DONE_FRAME_TYPE, PunchPair};

/// PUNCH_DONE Frame {
///     Type (i) = 0x3d7e96,
///     Link,
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deref)]
pub struct PunchDoneFrame {
    #[deref]
    punch_pair: Link,
}

impl PunchPair for PunchDoneFrame {
    fn punch_pair(&self) -> Option<Link> {
        Some(self.punch_pair)
    }
}

impl PunchDoneFrame {
    pub fn new(link: Link) -> Self {
        Self { punch_pair: link }
    }
}

pub fn be_punch_done_frame(input: &[u8]) -> nom::IResult<&[u8], PunchDoneFrame> {
    let (input, link) = be_link(input)?;
    Ok((input, PunchDoneFrame { punch_pair: link }))
}

impl GetFrameType for PunchDoneFrame {
    fn frame_type(&self) -> FrameType {
        FrameType::PunchDone
    }
}

impl EncodeSize for PunchDoneFrame {
    fn max_encoding_size(&self) -> usize {
        VarInt::from_u32(PUNCH_DONE_FRAME_TYPE).encoding_size() + self.punch_pair.encoding_size()
    }

    fn encoding_size(&self) -> usize {
        VarInt::from_u32(PUNCH_DONE_FRAME_TYPE).encoding_size() + self.punch_pair.encoding_size()
    }
}

impl<T: bytes::BufMut> io::WriteFrame<PunchDoneFrame> for T {
    fn put_frame(&mut self, frame: &PunchDoneFrame) {
        self.put_varint(&VarInt::from_u32(PUNCH_DONE_FRAME_TYPE));
        self.put_link(&frame.punch_pair);
    }
}
