use bytes::{BufMut, Bytes};
use qbase::{
    frame::{EncodeSize, Spec},
    net::{Family, tx::Signals},
    packet::{
        Package, PacketProperties, RecordFrame,
        r#type::{
            Type,
            long::{Type::V1, Ver1},
            short::OneRtt,
        },
    },
    util::NonData,
    varint::VarInt,
};

use super::{FrameType, TraversalFrame};
use crate::frame::{
    add_address::be_add_address_frame, collision::be_collistion_frame, konck::be_konck_frame,
    punch_done::be_punch_done_frame, punch_me_now::be_punch_me_now_frame,
    remove_address::be_remove_address_frame,
};

impl FrameType {
    pub fn belongs_to(&self, packet_type: Type) -> bool {
        let o = matches!(packet_type, Type::Long(V1(Ver1::ZERO_RTT)));
        let l = matches!(packet_type, Type::Short(OneRtt(_)));
        o || l
    }

    pub fn specs(&self) -> u8 {
        match self {
            FrameType::AddAddress(_) | FrameType::RemoveAddress | FrameType::PunchMeNow(_) => 0,
            FrameType::Konck | FrameType::PunchDone | FrameType::Collision => {
                Spec::NonAckEliciting as u8
            }
        }
    }

    pub fn is_ack_eliciting(&self) -> bool {
        match self {
            FrameType::AddAddress(_) | FrameType::RemoveAddress | FrameType::PunchMeNow(_) => true,
            FrameType::Konck | FrameType::PunchDone | FrameType::Collision => false,
        }
    }
}
impl TryFrom<VarInt> for FrameType {
    type Error = qbase::frame::error::Error;

    fn try_from(frame_type: VarInt) -> Result<Self, Self::Error> {
        Ok(match frame_type.into_inner() {
            0x3d7e90 => FrameType::AddAddress(Family::V4),
            0x3d7e91 => FrameType::AddAddress(Family::V6),
            0x3d7e92 => FrameType::PunchMeNow(Family::V4),
            0x3d7e93 => FrameType::PunchMeNow(Family::V6),
            0x3d7e94 => FrameType::RemoveAddress,
            0x3d7e95 => FrameType::Konck,
            0x3d7e96 => FrameType::PunchDone,
            0x3d7e97 => FrameType::Collision,
            _ => return Err(Self::Error::InvalidType(frame_type)),
        })
    }
}

fn complete_frame(frame_type: FrameType) -> impl Fn(&[u8]) -> nom::IResult<&[u8], TraversalFrame> {
    use nom::{Parser, combinator::map};
    move |input: &[u8]| match frame_type {
        FrameType::AddAddress(family) => {
            map(be_add_address_frame(family), TraversalFrame::AddAddress).parse(input)
        }
        FrameType::PunchMeNow(family) => {
            map(be_punch_me_now_frame(family), TraversalFrame::PunchMeNow).parse(input)
        }
        FrameType::RemoveAddress => {
            map(be_remove_address_frame, TraversalFrame::RemoveAddress).parse(input)
        }
        FrameType::Konck => map(be_konck_frame, TraversalFrame::Konck).parse(input),
        FrameType::PunchDone => map(be_punch_done_frame, TraversalFrame::PunchDone).parse(input),
        FrameType::Collision => map(be_collistion_frame, TraversalFrame::Collision).parse(input),
    }
}

pub fn be_frame_type(input: &[u8]) -> nom::IResult<&[u8], FrameType, qbase::frame::error::Error> {
    let (remain, frame_type) = qbase::varint::be_varint(input).map_err(|_| {
        nom::Err::Error(qbase::frame::error::Error::IncompleteType(format!(
            "Incomplete frame type from input: {input:?}"
        )))
    })?;
    let frame_type = FrameType::try_from(frame_type).map_err(nom::Err::Error)?;
    Ok((remain, frame_type))
}

pub fn be_frame(
    raw: &Bytes,
    packet_type: Type,
) -> Result<(usize, TraversalFrame, FrameType), qbase::frame::Error> {
    let input = raw.as_ref();
    let (remain, frame_type) = be_frame_type(input)?;
    if !frame_type.belongs_to(packet_type) {
        return Err(qbase::frame::Error::WrongType(
            qbase::frame::FrameType::Padding,
            packet_type,
        ));
    }

    let (remain, frame) = complete_frame(frame_type)(remain).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => {
            nom::Err::Error(qbase::frame::error::Error::IncompleteFrame(
                qbase::frame::FrameType::Padding,
                ne.to_string(),
            ))
        }
        nom::Err::Error(ne) => nom::Err::Error(qbase::frame::error::Error::ParseError(
            qbase::frame::FrameType::Padding,
            ne.code.description().to_owned(),
        )),
        _ => unreachable!("parsing frame never fails"),
    })?;
    Ok((input.len() - remain.len(), frame, frame_type))
}

pub trait WriteFrame<F>: bytes::BufMut {
    /// Write a frame to the buffer.
    fn put_frame(&mut self, frame: &F);
}

impl<T: BufMut> WriteFrame<TraversalFrame> for T {
    fn put_frame(&mut self, frame: &TraversalFrame) {
        match frame {
            TraversalFrame::AddAddress(frame) => self.put_frame(frame),
            TraversalFrame::RemoveAddress(frame) => self.put_frame(frame),
            TraversalFrame::PunchMeNow(frame) => self.put_frame(frame),
            TraversalFrame::Konck(frame) => self.put_frame(frame),
            TraversalFrame::PunchDone(frame) => self.put_frame(frame),
            TraversalFrame::Collision(frame) => self.put_frame(frame),
        }
    }
}

impl RecordFrame<TraversalFrame, NonData> for PacketProperties {
    #[inline]
    fn record_frame(&mut self, frame: &TraversalFrame) {
        self.add_frame(frame);
    }
}

impl<Target> Package<Target> for TraversalFrame
where
    Target: WriteFrame<TraversalFrame> + RecordFrame<TraversalFrame, NonData> + ?Sized,
{
    fn dump(&mut self, target: &mut Target) -> Result<(), Signals> {
        if !(target.remaining_mut() >= self.max_encoding_size()
            || target.remaining_mut() >= self.encoding_size())
        {
            return Err(Signals::CONGESTION);
        }
        let frame = self.clone();
        target.record_frame(&frame);
        target.put_frame(&frame);
        Ok(())
    }
}

impl<Target> Package<Target> for &TraversalFrame
where
    Target: WriteFrame<TraversalFrame> + RecordFrame<TraversalFrame, NonData> + ?Sized,
{
    fn dump(&mut self, target: &mut Target) -> Result<(), Signals> {
        if !(target.remaining_mut() >= self.max_encoding_size()
            || target.remaining_mut() >= self.encoding_size())
        {
            return Err(Signals::CONGESTION);
        }
        let frame = self.clone();
        target.record_frame(&frame);
        target.put_frame(&frame);
        Ok(())
    }
}
