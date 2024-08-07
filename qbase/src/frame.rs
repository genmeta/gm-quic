// This folder defines all the frames, including their parsing and packaging processes.
use enum_dispatch::enum_dispatch;

use crate::packet::r#type::Type;

#[enum_dispatch]
pub trait BeFrame {
    fn frame_type(&self) -> FrameType;

    // TODO: 这个应该取决于FrameType而非具体的Frame吧？
    fn belongs_to(&self, packet_type: Type) -> bool {
        self.frame_type().belongs_to(packet_type)
    }

    fn is_ack_eliciting(&self) -> bool {
        self.frame_type().is_ack_eliciting()
    }

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
mod datagram;
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
// re-export for convenience
pub use ack::{AckFrame, AckRecord, EcnCounts};
use bytes::{Buf, BufMut, Bytes};
pub use connection_close::ConnectionCloseFrame;
pub use crypto::CryptoFrame;
pub use data_blocked::DataBlockedFrame;
pub use datagram::DatagramFrame;
pub use error::Error;
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
    Datagram(u8),
}

impl FrameType {
    pub fn belongs_to(&self, packet_type: Type) -> bool {
        use crate::packet::r#type::{
            long::{Type::V1, Ver1},
            short::OneRtt,
        };
        // IH01
        let i = matches!(packet_type, Type::Long(V1(Ver1::INITIAL)));
        let h = matches!(packet_type, Type::Long(V1(Ver1::HANDSHAKE)));
        let o = matches!(packet_type, Type::Long(V1(Ver1::ZERO_RTT)));
        let l = matches!(packet_type, Type::Short(OneRtt(_)));

        match self {
            FrameType::Padding => i | h | o | l,
            FrameType::Ping => i | h | o | l,
            FrameType::Ack(_) => i | h | l,
            FrameType::ResetStream => o | l,
            FrameType::StopSending => o | l,
            FrameType::Crypto => i | h | l,
            FrameType::NewToken => l,
            FrameType::Stream(_) => o | l,
            FrameType::MaxData => o | l,
            FrameType::MaxStreamData => o | l,
            FrameType::MaxStreams(_) => o | l,
            FrameType::DataBlocked => o | l,
            FrameType::StreamDataBlocked => o | l,
            FrameType::StreamsBlocked(_) => o | l,
            FrameType::NewConnectionId => o | l,
            FrameType::RetireConnectionId => o | l,
            FrameType::PathChallenge => o | l,
            FrameType::PathResponse => l,
            FrameType::ConnectionClose(bit) => {
                if *bit == 0 && i || h {
                    true
                } else {
                    o | l
                }
            }
            FrameType::HandshakeDone => l,
            FrameType::Datagram(_) => o | l,
        }
    }

    pub fn is_ack_eliciting(&self) -> bool {
        let is_not_ack_eliciting = matches!(
            self,
            Self::Padding | Self::Ack(..) | Self::ConnectionClose(..)
        );
        !is_not_ack_eliciting
    }
}

impl TryFrom<u8> for FrameType {
    type Error = Error;

    fn try_from(frame_type: u8) -> Result<Self, Self::Error> {
        Ok(match frame_type {
            0x00 => FrameType::Padding,
            0x01 => FrameType::Ping,
            // The last bit is the ECN flag.
            ty @ (0x02 | 0x03) => FrameType::Ack(ty & 0b1),
            0x04 => FrameType::ResetStream,
            0x05 => FrameType::StopSending,
            0x06 => FrameType::Crypto,
            0x07 => FrameType::NewToken,
            // The last three bits are the offset, length, and fin flag bits respectively.
            ty @ 0x08..=0x0f => FrameType::Stream(ty & 0b111),
            0x10 => FrameType::MaxData,
            0x11 => FrameType::MaxStreamData,
            // The last bit is the direction flag bit, 0 indicates bidirectional, 1 indicates unidirectional.
            ty @ (0x12 | 0x13) => FrameType::MaxStreams(ty & 0b1),
            0x14 => FrameType::DataBlocked,
            0x15 => FrameType::StreamDataBlocked,
            // The last bit is the direction flag bit, 0 indicates bidirectional, 1 indicates unidirectional.
            ty @ (0x16 | 0x17) => FrameType::StreamsBlocked(ty & 0b1),
            0x18 => FrameType::NewConnectionId,
            0x19 => FrameType::RetireConnectionId,
            0x1a => FrameType::PathChallenge,
            0x1b => FrameType::PathResponse,
            // The last bit is the layer flag bit, 0 indicates application layer, 1 indicates transport layer.
            ty @ (0x1c | 0x1d) => FrameType::ConnectionClose(ty & 0x1),
            0x1e => FrameType::HandshakeDone,
            ty @ (0x30 | 0x31) => FrameType::Datagram(ty & 1),
            _ => return Err(Self::Error::InvalidType(VarInt::from(frame_type))),
        })
    }
}

impl From<FrameType> for u8 {
    fn from(frame_type: FrameType) -> Self {
        match frame_type {
            FrameType::Padding => 0x00,
            FrameType::Ping => 0x01,
            FrameType::Ack(ecn) => 0x02 | ecn,
            FrameType::ResetStream => 0x04,
            FrameType::StopSending => 0x05,
            FrameType::Crypto => 0x06,
            FrameType::NewToken => 0x07,
            FrameType::Stream(flag) => 0x08 | flag,
            FrameType::MaxData => 0x10,
            FrameType::MaxStreamData => 0x11,
            FrameType::MaxStreams(dir) => 0x12 | dir,
            FrameType::DataBlocked => 0x14,
            FrameType::StreamDataBlocked => 0x15,
            FrameType::StreamsBlocked(dir) => 0x16 | dir,
            FrameType::NewConnectionId => 0x18,
            FrameType::RetireConnectionId => 0x19,
            FrameType::PathChallenge => 0x1a,
            FrameType::PathResponse => 0x1b,
            FrameType::ConnectionClose(layer) => 0x1c | layer,
            FrameType::HandshakeDone => 0x1e,
            FrameType::Datagram(with_len) => 0x30 | with_len,
        }
    }
}

pub trait WriteFrameType {
    fn put_frame_type(&mut self, frame: FrameType);
}

impl<T: BufMut> WriteFrameType for T {
    fn put_frame_type(&mut self, frame: FrameType) {
        self.put_u8(frame.into())
    }
}

pub fn be_frame_type(input: &[u8]) -> nom::IResult<&[u8], FrameType, Error> {
    let (remain, frame_type) = nom::number::complete::be_u8(input)?;
    let frame_type = FrameType::try_from(frame_type).map_err(nom::Err::Error)?;
    Ok((remain, frame_type))
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
pub enum DataFrame {
    Crypto(CryptoFrame),
    Stream(StreamFrame),
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(BeFrame)]
pub enum ReliableFrame {
    NewToken(NewTokenFrame),
    MaxData(MaxDataFrame),
    DataBlocked(DataBlockedFrame),
    NewConnectionId(NewConnectionIdFrame),
    RetireConnectionId(RetireConnectionIdFrame),
    HandshakeDone(HandshakeDoneFrame),
    Stream(StreamCtlFrame),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Frame {
    Padding(PaddingFrame),
    Ping(PingFrame),
    Ack(AckFrame),
    Close(ConnectionCloseFrame),
    NewToken(NewTokenFrame),
    MaxData(MaxDataFrame),
    DataBlocked(DataBlockedFrame),
    NewConnectionId(NewConnectionIdFrame),
    RetireConnectionId(RetireConnectionIdFrame),
    HandshakeDone(HandshakeDoneFrame),
    Challenge(PathChallengeFrame),
    Response(PathResponseFrame),
    Stream(StreamCtlFrame),
    Data(DataFrame, Bytes),
    Datagram(DatagramFrame, Bytes),
}

/*
impl BeFrame for Frame {
    fn frame_type(&self) -> FrameType {
        match self {
            Frame::Padding(f) => f.frame_type(),
            Frame::Ping(f) => f.frame_type(),
            Frame::Ack(f) => f.frame_type(),
            Frame::Close(f) => f.frame_type(),
            Frame::NewToken(f) => f.frame_type(),
            Frame::MaxData(f) => f.frame_type(),
            Frame::DataBlocked(f) => f.frame_type(),
            Frame::NewConnectionId(f) => f.frame_type(),
            Frame::RetireConnectionId(f) => f.frame_type(),
            Frame::HandshakeDone(f) => f.frame_type(),
            Frame::Challenge(f) => f.frame_type(),
            Frame::Response(f) => f.frame_type(),
            Frame::Stream(f) => f.frame_type(),
            Frame::Data(f, _) => f.frame_type(),
            Frame::Datagram(f, _) => f.frame_type(),
        }
    }

    fn encoding_size(&self) -> usize {
        match self {
            Frame::Padding(f) => f.encoding_size(),
            Frame::Ping(f) => f.encoding_size(),
            Frame::Ack(f) => f.encoding_size(),
            Frame::Close(f) => f.encoding_size(),
            Frame::NewToken(f) => f.encoding_size(),
            Frame::MaxData(f) => f.encoding_size(),
            Frame::DataBlocked(f) => f.encoding_size(),
            Frame::NewConnectionId(f) => f.encoding_size(),
            Frame::RetireConnectionId(f) => f.encoding_size(),
            Frame::HandshakeDone(f) => f.encoding_size(),
            Frame::Challenge(f) => f.encoding_size(),
            Frame::Response(f) => f.encoding_size(),
            Frame::Stream(f) => f.encoding_size(),
            Frame::Data(f, d) => f.encoding_size() + d.len(),
            Frame::Datagram(f, d) => f.encoding_size() + d.len(),
        }
    }

    fn max_encoding_size(&self) -> usize {
        match self {
            Frame::Padding(f) => f.max_encoding_size(),
            Frame::Ping(f) => f.max_encoding_size(),
            Frame::Ack(f) => f.max_encoding_size(),
            Frame::Close(f) => f.max_encoding_size(),
            Frame::NewToken(f) => f.max_encoding_size(),
            Frame::MaxData(f) => f.max_encoding_size(),
            Frame::DataBlocked(f) => f.max_encoding_size(),
            Frame::NewConnectionId(f) => f.max_encoding_size(),
            Frame::RetireConnectionId(f) => f.max_encoding_size(),
            Frame::HandshakeDone(f) => f.max_encoding_size(),
            Frame::Challenge(f) => f.max_encoding_size(),
            Frame::Response(f) => f.max_encoding_size(),
            Frame::Stream(f) => f.max_encoding_size(),
            Frame::Data(f, d) => f.max_encoding_size() + d.len(),
            Frame::Datagram(f, d) => f.max_encoding_size() + d.len(),
        }
    }
}
*/

pub struct FrameReader {
    payload: Bytes,
    packet_type: Type,
}

impl FrameReader {
    pub fn new(payload: Bytes, packet_type: Type) -> Self {
        Self {
            payload,
            packet_type,
        }
    }
}

pub mod io;

impl Iterator for FrameReader {
    type Item = Result<(Frame, bool), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.payload.is_empty() {
            return None;
        }

        match io::be_frame(&self.payload, self.packet_type) {
            Ok((consumed, frame, is_ack_eliciting)) => {
                self.payload.advance(consumed);
                Some(Ok((frame, is_ack_eliciting)))
            }
            Err(e) => {
                self.payload.clear(); // no longer parsing
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {}
