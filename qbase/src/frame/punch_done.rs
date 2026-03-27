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

/// PUNCH_DONE Frame {
///     Type (i) = 0x3d7e96,
///     Link,
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deref)]
pub struct PunchDoneFrame {
    #[deref]
    punch_pair: Link<SocketAddr>,
}

impl PunchDoneFrame {
    pub fn new(link: Link<SocketAddr>) -> Self {
        Self { punch_pair: link }
    }
}

pub(crate) fn be_punch_done_frame(input: &[u8]) -> nom::IResult<&[u8], PunchDoneFrame> {
    let (input, link) = be_link(input)?;
    Ok((input, PunchDoneFrame { punch_pair: link }))
}

impl GetFrameType for PunchDoneFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PunchDone
    }
}

impl EncodeSize for PunchDoneFrame {
    fn max_encoding_size(&self) -> usize {
        4 + self.punch_pair.max_encoding_size()
    }

    fn encoding_size(&self) -> usize {
        VarInt::from(self.frame_type()).encoding_size() + self.punch_pair.encoding_size()
    }
}

impl<T: bytes::BufMut> WriteFrame<PunchDoneFrame> for T {
    fn put_frame(&mut self, frame: &PunchDoneFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_link(&frame.punch_pair);
    }
}
