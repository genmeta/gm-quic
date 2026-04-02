use std::net::SocketAddr;

use derive_more::Deref;

use super::{
    EncodeSize, GetFrameType,
    io::{WriteFrame, WriteFrameType},
};
use crate::{
    net::route::{Link, WriteLink, be_link},
    varint::VarInt,
};

/// PUNCH_KNOCK Frame {
///     Type (i) = 0x3d7e95,
///     Link,
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deref)]
pub struct PunchKnockFrame {
    #[deref]
    punch_pair: Link<SocketAddr>,
}

impl PunchKnockFrame {
    pub fn new(link: Link<SocketAddr>) -> Self {
        Self { punch_pair: link }
    }
}

pub(crate) fn be_punch_knock_frame(input: &[u8]) -> nom::IResult<&[u8], PunchKnockFrame> {
    let (input, link) = be_link(input)?;
    Ok((input, PunchKnockFrame { punch_pair: link }))
}

impl GetFrameType for PunchKnockFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PunchKnock
    }
}

impl EncodeSize for PunchKnockFrame {
    fn max_encoding_size(&self) -> usize {
        4 + self.punch_pair.max_encoding_size()
    }

    fn encoding_size(&self) -> usize {
        VarInt::from(self.frame_type()).encoding_size() + self.punch_pair.encoding_size()
    }
}

impl<T: bytes::BufMut> WriteFrame<PunchKnockFrame> for T {
    fn put_frame(&mut self, frame: &PunchKnockFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_link(&frame.punch_pair);
    }
}
