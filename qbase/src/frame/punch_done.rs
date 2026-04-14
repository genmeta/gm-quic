use super::{
    EncodeSize, GetFrameType,
    io::{WriteFrame, WriteFrameType},
};
use crate::varint::{VarInt, WriteVarInt, be_varint};

/// PUNCH_Done Frame {
///     Type (i) = 0x3d7e96,
///     Local Sequence Number (i),
///     Remote Sequence Number (i),
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchDoneFrame {
    local_seq: VarInt,
    remote_seq: VarInt,
}

impl PunchDoneFrame {
    pub fn new(local_seq: u32, remote_seq: u32) -> Self {
        Self {
            local_seq: VarInt::from_u32(local_seq),
            remote_seq: VarInt::from_u32(remote_seq),
        }
    }

    pub fn local_seq(&self) -> u32 {
        self.local_seq.into_inner() as u32
    }

    pub fn remote_seq(&self) -> u32 {
        self.remote_seq.into_inner() as u32
    }
}

impl GetFrameType for PunchDoneFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PunchDone
    }
}

impl EncodeSize for PunchDoneFrame {
    fn max_encoding_size(&self) -> usize {
        4 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        VarInt::from(self.frame_type()).encoding_size()
            + self.local_seq.encoding_size()
            + self.remote_seq.encoding_size()
    }
}

impl<T: bytes::BufMut> WriteFrame<PunchDoneFrame> for T {
    fn put_frame(&mut self, frame: &PunchDoneFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_varint(&frame.local_seq);
        self.put_varint(&frame.remote_seq);
    }
}

pub(crate) fn be_punch_done_frame(input: &[u8]) -> nom::IResult<&[u8], PunchDoneFrame> {
    let (input, local_seq) = be_varint(input)?;
    let (input, remote_seq) = be_varint(input)?;
    Ok((
        input,
        PunchDoneFrame {
            local_seq,
            remote_seq,
        },
    ))
}
