// This folder defines all the frames, including their parsing and packaging processes.
use crate::packet::r#type::Type;
use enum_dispatch::enum_dispatch;

#[enum_dispatch]
pub trait BeFrame {
    fn frame_type(&self) -> FrameType;

    fn belongs_to(&self, packet_type: Type) -> bool;

    fn max_encoding_size(&self) -> usize {
        1
    }

    fn encoding_size(&self) -> usize {
        1
    }
}

mod ack;
mod connection_close;
mod crypto;
mod data_blocked;
mod handshake_done;
mod max_data;
mod max_stream_data;
mod max_streams;
mod new_connection_id;
mod new_token;
mod padding;
mod path_challenge;
mod path_response;
mod ping;
mod reset_stream;
mod retire_connection_id;
mod stop_sending;
mod stream;
mod stream_data_blocked;
mod streams_blocked;

pub mod error;
pub use error::Error;

// re-export for convenience
pub use ack::{AckFrame, AckRecord};
pub use connection_close::ConnectionCloseFrame;
pub use crypto::CryptoFrame;
pub use data_blocked::DataBlockedFrame;
pub use handshake_done::HandshakeDoneFrame;
pub use max_data::MaxDataFrame;
pub use max_stream_data::MaxStreamDataFrame;
pub use max_streams::MaxStreamsFrame;
pub use new_connection_id::NewConnectionIdFrame;
pub use new_token::NewTokenFrame;
pub use padding::PaddingFrame;
pub use path_challenge::PathChallengeFrame;
pub use path_response::PathResponseFrame;
pub use ping::PingFrame;
pub use reset_stream::ResetStreamFrame;
pub use retire_connection_id::RetireConnectionIdFrame;
pub use stop_sending::StopSendingFrame;
pub use stream::{ShouldCarryLength, StreamFrame};
pub use stream_data_blocked::StreamDataBlockedFrame;
pub use streams_blocked::StreamsBlockedFrame;

use super::varint::VarInt;
use bytes::{Buf, Bytes};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FrameType {
    Padding,
    Ping,
    Ack(u8),
    ResetStream,
    StopSending,
    Crypto,
    NewToken,
    Stream(u8),
    MaxData,
    MaxStreamData,
    MaxStreams(u8),
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked(u8),
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionClose(u8),
    HandshakeDone,
}

impl TryFrom<VarInt> for FrameType {
    type Error = Error;

    fn try_from(frame_type: VarInt) -> Result<Self, Self::Error> {
        Ok(match frame_type.into_inner() {
            0x00 => FrameType::Padding,
            0x01 => FrameType::Ping,
            // The last bit is the ECN flag.
            ty @ (0x02 | 0x03) => FrameType::Ack(ty as u8 & 0b1),
            0x04 => FrameType::ResetStream,
            0x05 => FrameType::StopSending,
            0x06 => FrameType::Crypto,
            0x07 => FrameType::NewToken,
            // The last three bits are the offset, length, and fin flag bits respectively.
            ty @ 0x08..=0x0f => FrameType::Stream(ty as u8 & 0b111),
            0x10 => FrameType::MaxData,
            0x11 => FrameType::MaxStreamData,
            // The last bit is the direction flag bit, 0 indicates bidirectional, 1 indicates unidirectional.
            ty @ (0x12 | 0x13) => FrameType::MaxStreams(ty as u8 & 0b1),
            0x14 => FrameType::DataBlocked,
            0x15 => FrameType::StreamDataBlocked,
            // The last bit is the direction flag bit, 0 indicates bidirectional, 1 indicates unidirectional.
            ty @ (0x16 | 0x17) => FrameType::StreamsBlocked(ty as u8 & 0b1),
            0x18 => FrameType::NewConnectionId,
            0x19 => FrameType::RetireConnectionId,
            0x1a => FrameType::PathChallenge,
            0x1b => FrameType::PathResponse,
            // The last bit is the layer flag bit, 0 indicates application layer, 1 indicates transport layer.
            ty @ (0x1c | 0x1d) => FrameType::ConnectionClose(ty as u8 & 0x1),
            0x1e => FrameType::HandshakeDone,
            _ => return Err(Self::Error::InvalidType(frame_type)),
        })
    }
}

impl From<FrameType> for VarInt {
    fn from(frame_type: FrameType) -> Self {
        match frame_type {
            FrameType::Padding => VarInt(0x00),
            FrameType::Ping => VarInt(0x01),
            FrameType::Ack(ecn) => VarInt(0x02 | ecn as u64),
            FrameType::ResetStream => VarInt(0x04),
            FrameType::StopSending => VarInt(0x05),
            FrameType::Crypto => VarInt(0x06),
            FrameType::NewToken => VarInt(0x07),
            FrameType::Stream(flag) => VarInt(0x08 | flag as u64),
            FrameType::MaxData => VarInt(0x10),
            FrameType::MaxStreamData => VarInt(0x11),
            FrameType::MaxStreams(dir) => VarInt(0x12 | dir as u64),
            FrameType::DataBlocked => VarInt(0x14),
            FrameType::StreamDataBlocked => VarInt(0x15),
            FrameType::StreamsBlocked(dir) => VarInt(0x16 | dir as u64),
            FrameType::NewConnectionId => VarInt(0x18),
            FrameType::RetireConnectionId => VarInt(0x19),
            FrameType::PathChallenge => VarInt(0x1a),
            FrameType::PathResponse => VarInt(0x1b),
            FrameType::ConnectionClose(layer) => VarInt(0x1c | layer as u64),
            FrameType::HandshakeDone => VarInt(0x1e),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(BeFrame)]
pub enum ConnFrame {
    Close(ConnectionCloseFrame),
    NewToken(NewTokenFrame),
    MaxData(MaxDataFrame),
    DataBlocked(DataBlockedFrame),
    NewConnectionId(NewConnectionIdFrame),
    RetireConnectionId(RetireConnectionIdFrame),
    HandshakeDone(HandshakeDoneFrame),
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(BeFrame)]
pub enum StreamCtlFrame {
    ResetStream(ResetStreamFrame),
    StopSending(StopSendingFrame),
    MaxStreamData(MaxStreamDataFrame),
    MaxStreams(MaxStreamsFrame),
    StreamDataBlocked(StreamDataBlockedFrame),
    StreamsBlocked(StreamsBlockedFrame),
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(BeFrame)]
pub enum PathFrame {
    Challenge(PathChallengeFrame),
    Response(PathResponseFrame),
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(BeFrame)]
pub enum DataFrame {
    Crypto(CryptoFrame),
    Stream(StreamFrame),
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(BeFrame)]
pub enum PureFrame {
    Padding(PaddingFrame),
    Ping(PingFrame),
    Ack(AckFrame),
    Conn(ConnFrame),
    Stream(StreamCtlFrame),
    Path(PathFrame),
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(BeFrame)]
pub enum ReliableFrame {
    Conn(ConnFrame),
    Stream(StreamCtlFrame),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Frame {
    Pure(PureFrame),
    Data(DataFrame, Bytes),
}

pub struct FrameReader {
    raw: Bytes,
}

impl FrameReader {
    pub fn new(raw: Bytes) -> Self {
        Self { raw }
    }
}

pub mod io;

impl Iterator for FrameReader {
    type Item = Result<Frame, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }

        match io::be_frame(&self.raw) {
            Ok((consumed, frame)) => {
                self.raw.advance(consumed);
                Some(Ok(frame))
            }
            Err(e) => {
                self.raw.clear(); // no longer parsing
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {}
