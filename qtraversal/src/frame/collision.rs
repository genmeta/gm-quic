use derive_more::Deref;
use qbase::{
    frame::EncodeSize,
    net::route::{WriteLink, be_link},
    varint::{VarInt, WriteVarInt},
};

use super::{FrameType, GetFrameType, io};
use crate::{
    Link,
    frame::{COLLISION_FRAME_TYPE, PunchPair},
};

/// CollisionFrame Frame {
///     Type (i) = 0x3d7e97,
///     Link,
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deref)]
pub struct CollisionFrame {
    #[deref]
    link: Link,
}

impl CollisionFrame {
    pub fn new(link: Link) -> Self {
        Self { link }
    }
}

impl PunchPair for CollisionFrame {
    fn punch_pair(&self) -> Option<Link> {
        Some(self.link)
    }
}

pub fn be_collistion_frame(input: &[u8]) -> nom::IResult<&[u8], CollisionFrame> {
    let (input, link) = be_link(input)?;
    Ok((input, CollisionFrame { link }))
}

impl GetFrameType for CollisionFrame {
    fn frame_type(&self) -> FrameType {
        FrameType::Collision
    }
}

impl EncodeSize for CollisionFrame {
    fn max_encoding_size(&self) -> usize {
        VarInt::from_u32(COLLISION_FRAME_TYPE).encoding_size() + self.link.max_encoding_size()
    }

    fn encoding_size(&self) -> usize {
        VarInt::from_u32(COLLISION_FRAME_TYPE).encoding_size() + self.link.encoding_size()
    }
}

impl<T: bytes::BufMut> io::WriteFrame<CollisionFrame> for T {
    fn put_frame(&mut self, frame: &CollisionFrame) {
        self.put_varint(&VarInt::from_u32(COLLISION_FRAME_TYPE));
        self.put_link(&frame.link);
    }
}
