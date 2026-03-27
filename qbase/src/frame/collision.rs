use std::net::SocketAddr;

use derive_more::Deref;

use super::{
    EncodeSize, FrameType, GetFrameType,
    io::{WriteFrame, WriteFrameType},
};
use crate::{
    net::route::{Link, WriteLink, be_link},
    varint::VarInt,
};

/// CollisionFrame Frame {
///     Type (i) = 0x3d7e97,
///     Link,
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deref)]
pub struct CollisionFrame {
    #[deref]
    link: Link<SocketAddr>,
}

impl CollisionFrame {
    pub fn new(link: Link<SocketAddr>) -> Self {
        Self { link }
    }
}

pub(crate) fn be_collision_frame(input: &[u8]) -> nom::IResult<&[u8], CollisionFrame> {
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
        4 + self.link.max_encoding_size()
    }

    fn encoding_size(&self) -> usize {
        VarInt::from(self.frame_type()).encoding_size() + self.link.encoding_size()
    }
}

impl<T: bytes::BufMut> WriteFrame<CollisionFrame> for T {
    fn put_frame(&mut self, frame: &CollisionFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_link(&frame.link);
    }
}
