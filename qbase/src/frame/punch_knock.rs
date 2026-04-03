use super::{
    EncodeSize, GetFrameType,
    io::{WriteFrame, WriteFrameType},
};
use crate::varint::{VarInt, WriteVarInt, be_varint};

/// PUNCH_KNOCK Frame {
///     Type (i) = 0x3d7e95 (Knock) | 0x3d7e96 (Done),
///     Local Sequence Number (i),
///     Remote Sequence Number (i),
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchKnockFrame {
    is_done: bool,
    local_seq: VarInt,
    remote_seq: VarInt,
}

impl PunchKnockFrame {
    pub fn new(local_seq: u32, remote_seq: u32) -> Self {
        Self {
            is_done: false,
            local_seq: VarInt::from_u32(local_seq),
            remote_seq: VarInt::from_u32(remote_seq),
        }
    }

    pub fn done(local_seq: u32, remote_seq: u32) -> Self {
        Self {
            is_done: true,
            local_seq: VarInt::from_u32(local_seq),
            remote_seq: VarInt::from_u32(remote_seq),
        }
    }

    pub fn is_done(&self) -> bool {
        self.is_done
    }

    pub fn local_seq(&self) -> u32 {
        self.local_seq.into_inner() as u32
    }

    pub fn remote_seq(&self) -> u32 {
        self.remote_seq.into_inner() as u32
    }
}

pub(crate) fn be_punch_knock_frame(
    is_done: bool,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], PunchKnockFrame> {
    move |input: &[u8]| {
        let (input, local_seq) = be_varint(input)?;
        let (input, remote_seq) = be_varint(input)?;
        Ok((
            input,
            PunchKnockFrame {
                is_done,
                local_seq,
                remote_seq,
            },
        ))
    }
}

impl GetFrameType for PunchKnockFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PunchKnock(self.is_done)
    }
}

impl EncodeSize for PunchKnockFrame {
    fn max_encoding_size(&self) -> usize {
        4 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        VarInt::from(self.frame_type()).encoding_size()
            + self.local_seq.encoding_size()
            + self.remote_seq.encoding_size()
    }
}

impl<T: bytes::BufMut> WriteFrame<PunchKnockFrame> for T {
    fn put_frame(&mut self, frame: &PunchKnockFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_varint(&frame.local_seq);
        self.put_varint(&frame.remote_seq);
    }
}
