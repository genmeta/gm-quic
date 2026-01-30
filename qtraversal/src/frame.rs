use std::fmt::Debug;

use add_address::AddAddressFrame;
use enum_dispatch::enum_dispatch;
use punch_me_now::PunchMeNowFrame;
use qbase::{
    frame::{EncodeSize, FrameFeature},
    net::Family,
    packet::r#type::Type,
};
use remove_address::RemoveAddressFrame;

use crate::{
    Link,
    frame::{collision::CollisionFrame, konck::KonckFrame, punch_done::PunchDoneFrame},
};

pub mod add_address;
pub mod collision;
pub mod io;
pub mod konck;
pub mod punch_done;
pub mod punch_me_now;
pub mod remove_address;

// TODO；移动到 qbase
pub const ADD_ADDRESS_FRAME_TYPE: u32 = 0x3d7e90; // 0x3d7e90 for IPv4, 0x3d7e91 for IPv6
pub const PUNCH_ME_NOW_FRAME_TYPE: u32 = 0x3d7e92; // 0x3d7e92 for IPv4, 0x3d7e93 for IPv6
pub const REMOVE_ADDRESS_FRAME_TYPE: u32 = 0x3d7e94;
pub const KONCK_FRAME_TYPE: u32 = 0x3d7e95;
pub const PUNCH_DONE_FRAME_TYPE: u32 = 0x3d7e96;
pub const COLLISION_FRAME_TYPE: u32 = 0x3d7e97;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FrameType {
    /// ADD_ADDRESS frame, see [`AddAddressFrame`].
    AddAddress(Family),
    /// REMOVE_ADDRESS frame, see [`RemoveAddressFrame`].
    RemoveAddress,
    /// PUNCH_ME_NOW frame, see [`PunchMeNowFrame`].
    PunchMeNow(Family),
    /// Konck frame, see [`KonckFrame`].
    Konck,
    /// Punch done frame, see [`PunchDoneFrame`].
    PunchDone,
    /// Collision frame, see [`CollisionFrame`].
    Collision,
}

impl From<FrameType> for u32 {
    fn from(value: FrameType) -> Self {
        match value {
            FrameType::AddAddress(family) => ADD_ADDRESS_FRAME_TYPE | family as u32,
            FrameType::RemoveAddress => REMOVE_ADDRESS_FRAME_TYPE,
            FrameType::PunchMeNow(family) => PUNCH_ME_NOW_FRAME_TYPE | family as u32,
            FrameType::Konck => KONCK_FRAME_TYPE,
            FrameType::PunchDone => PUNCH_DONE_FRAME_TYPE,
            FrameType::Collision => COLLISION_FRAME_TYPE,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(GetFrameType, PunchPair)]
pub enum TraversalFrame {
    /// ADD_ADDRESS frame, see [`AddAddressFrame`].
    AddAddress(AddAddressFrame),
    /// REMOVE_ADDRESS frame, see [`RemoveAddressFrame`].
    RemoveAddress(RemoveAddressFrame),
    /// PUNCH_ME_NOW frame, see [`PunchMeNowFrame`].
    PunchMeNow(PunchMeNowFrame),
    /// Konck frame, see [`KonckFrame`].
    Konck(KonckFrame),
    /// Punch done frame, see [`PunchDoneFrame`].
    PunchDone(PunchDoneFrame),
    /// Collision frame, see [`CollisionFrame`].
    Collision(CollisionFrame),
}

impl EncodeSize for TraversalFrame {
    fn max_encoding_size(&self) -> usize {
        match self {
            TraversalFrame::AddAddress(frame) => frame.max_encoding_size(),
            TraversalFrame::RemoveAddress(frame) => frame.max_encoding_size(),
            TraversalFrame::PunchMeNow(frame) => frame.max_encoding_size(),
            TraversalFrame::Konck(frame) => frame.max_encoding_size(),
            TraversalFrame::PunchDone(frame) => frame.max_encoding_size(),
            TraversalFrame::Collision(frame) => frame.max_encoding_size(),
        }
    }

    fn encoding_size(&self) -> usize {
        match self {
            TraversalFrame::AddAddress(frame) => frame.encoding_size(),
            TraversalFrame::RemoveAddress(frame) => frame.encoding_size(),
            TraversalFrame::PunchMeNow(frame) => frame.encoding_size(),
            TraversalFrame::Konck(frame) => frame.encoding_size(),
            TraversalFrame::PunchDone(frame) => frame.encoding_size(),
            TraversalFrame::Collision(frame) => frame.encoding_size(),
        }
    }
}

impl From<&TraversalFrame> for qevent::quic::QuicFrame {
    fn from(value: &TraversalFrame) -> Self {
        Self::Unknow {
            frame_type_bytes: u32::from(value.frame_type()) as _,
            raw: None, // TODO
        }
    }
}

#[enum_dispatch]
pub(crate) trait PunchPair {
    fn punch_pair(&self) -> Option<Link>;
}

#[enum_dispatch]
pub trait GetFrameType {
    fn frame_type(&self) -> FrameType;
}

impl FrameFeature for TraversalFrame {
    fn belongs_to(&self, packet_type: Type) -> bool {
        self.frame_type().belongs_to(packet_type)
    }

    fn specs(&self) -> u8 {
        self.frame_type().specs()
    }
}
