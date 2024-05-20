// This folder defines all the frames, including their parsing and packaging processes.
use crate::SpaceId;
use enum_dispatch::enum_dispatch;

#[enum_dispatch]
pub trait BeFrame {
    fn frame_type(&self) -> FrameType;

    fn belongs_to(&self, _space_id: SpaceId) -> bool {
        true
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
pub enum StreamInfoFrame {
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
    Conn(ConnFrame),
    Stream(StreamInfoFrame),
    Path(PathFrame),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Frame {
    Padding,
    Ping(PingFrame),
    Ack(AckFrame),
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

impl Iterator for FrameReader {
    type Item = Result<Frame, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }

        match ext::be_frame(&self.raw) {
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

pub mod ext {
    use super::{
        ack::ext::ack_frame_with_flag, connection_close::ext::connection_close_frame_at_layer,
        crypto::ext::be_crypto_frame, data_blocked::ext::be_data_blocked_frame,
        handshake_done::ext::WriteHandshakeDoneFrame, max_data::ext::be_max_data_frame,
        max_stream_data::ext::be_max_stream_data_frame,
        max_streams::ext::max_streams_frame_with_dir,
        new_connection_id::ext::be_new_connection_id_frame, new_token::ext::be_new_token_frame,
        new_token::ext::WriteNewTokenFrame, path_challenge::ext::be_path_challenge_frame,
        path_response::ext::be_path_response_frame, reset_stream::ext::be_reset_stream_frame,
        retire_connection_id::ext::be_retire_connection_id_frame,
        stop_sending::ext::be_stop_sending_frame, stream::ext::stream_frame_with_flag,
        stream_data_blocked::ext::be_stream_data_blocked_frame,
        streams_blocked::ext::streams_blocked_frame_with_dir, *,
    };
    use bytes::Bytes;

    /// Some frames like `STREAM` and `CRYPTO` have a data body, which use `bytes::Bytes` to store.
    fn complete_frame(
        frame_type: FrameType,
        raw: Bytes,
    ) -> impl Fn(&[u8]) -> nom::IResult<&[u8], Frame> {
        use nom::combinator::map;
        move |input: &[u8]| match frame_type {
            FrameType::Padding => Ok((input, Frame::Padding)),
            FrameType::Ping => Ok((input, Frame::Ping(PingFrame))),
            FrameType::ConnectionClose(layer) => map(connection_close_frame_at_layer(layer), |f| {
                Frame::Pure(PureFrame::Conn(ConnFrame::Close(f)))
            })(input),
            FrameType::NewConnectionId => map(be_new_connection_id_frame, |f| {
                Frame::Pure(PureFrame::Conn(ConnFrame::NewConnectionId(f)))
            })(input),
            FrameType::RetireConnectionId => map(be_retire_connection_id_frame, |f| {
                Frame::Pure(PureFrame::Conn(ConnFrame::RetireConnectionId(f)))
            })(input),
            FrameType::DataBlocked => map(be_data_blocked_frame, |f| {
                Frame::Pure(PureFrame::Conn(ConnFrame::DataBlocked(f)))
            })(input),
            FrameType::MaxData => map(be_max_data_frame, |f| {
                Frame::Pure(PureFrame::Conn(ConnFrame::MaxData(f)))
            })(input),
            FrameType::PathChallenge => map(be_path_challenge_frame, |f| {
                Frame::Pure(PureFrame::Path(PathFrame::Challenge(f)))
            })(input),
            FrameType::PathResponse => map(be_path_response_frame, |f| {
                Frame::Pure(PureFrame::Path(PathFrame::Response(f)))
            })(input),
            FrameType::HandshakeDone => Ok((
                input,
                Frame::Pure(PureFrame::Conn(ConnFrame::HandshakeDone(
                    HandshakeDoneFrame,
                ))),
            )),
            FrameType::NewToken => map(be_new_token_frame, |f| {
                Frame::Pure(PureFrame::Conn(ConnFrame::NewToken(f)))
            })(input),
            FrameType::Ack(ecn) => map(ack_frame_with_flag(ecn), Frame::Ack)(input),
            FrameType::ResetStream => map(be_reset_stream_frame, |f| {
                Frame::Pure(PureFrame::Stream(f.into()))
            })(input),
            FrameType::StopSending => map(be_stop_sending_frame, |f| {
                Frame::Pure(PureFrame::Stream(f.into()))
            })(input),
            FrameType::MaxStreamData => map(be_max_stream_data_frame, |f| {
                Frame::Pure(PureFrame::Stream(f.into()))
            })(input),
            FrameType::MaxStreams(dir) => map(max_streams_frame_with_dir(dir), |f| {
                Frame::Pure(PureFrame::Stream(f.into()))
            })(input),
            FrameType::StreamsBlocked(dir) => map(streams_blocked_frame_with_dir(dir), |f| {
                Frame::Pure(PureFrame::Stream(f.into()))
            })(input),
            FrameType::StreamDataBlocked => map(be_stream_data_blocked_frame, |f| {
                Frame::Pure(PureFrame::Stream(f.into()))
            })(input),
            FrameType::Crypto => {
                let (input, frame) = be_crypto_frame(input)?;
                let start = raw.len() - input.len();
                let len = frame.length.into_inner() as usize;
                if input.len() < len {
                    Err(nom::Err::Incomplete(nom::Needed::new(len - input.len())))
                } else {
                    let data = raw.slice(start..start + len);
                    Ok((&input[len..], Frame::Data(DataFrame::Crypto(frame), data)))
                }
            }
            FrameType::Stream(flag) => {
                let (input, frame) = stream_frame_with_flag(flag)(input)?;
                let start = raw.len() - input.len();
                let len = frame.length;
                if input.len() < len {
                    Err(nom::Err::Incomplete(nom::Needed::new(len - input.len())))
                } else {
                    let data = raw.slice(start..start + len);
                    Ok((&input[len..], Frame::Data(DataFrame::Stream(frame), data)))
                }
            }
        }
    }

    pub(super) fn be_frame(raw: &Bytes) -> Result<(usize, Frame), Error> {
        use crate::varint::ext::be_varint;
        let input = raw.as_ref();
        let (remain, fty) = be_varint(input).map_err(|e| match e {
            ne @ nom::Err::Incomplete(_) => nom::Err::Error(Error::IncompleteType(ne.to_string())),
            _ => unreachable!(
                "parsing frame type which is a varint never generates error or failure"
            ),
        })?;
        let frame_type = FrameType::try_from(fty).map_err(nom::Err::Error)?;
        let (remain, frame) =
            complete_frame(frame_type, raw.clone())(remain).map_err(|e| match e {
                ne @ nom::Err::Incomplete(_) => {
                    nom::Err::Error(Error::IncompleteFrame(frame_type, ne.to_string()))
                }
                nom::Err::Error(ne) => {
                    // may be TooLarge in MaxStreamsFrame/CryptoFrame/StreamFrame,
                    // or may be Verify in NewConnectionIdFrame,
                    // or may be Alt in ConnectionCloseFrame
                    nom::Err::Error(Error::ParseError(
                        frame_type,
                        ne.code.description().to_owned(),
                    ))
                }
                _ => unreachable!("parsing frame never fails"),
            })?;
        Ok((input.len() - remain.len(), frame))
    }

    use super::{
        data_blocked::ext::WriteDataBlockedFrame, max_data::ext::WriteMaxDataFrame,
        max_stream_data::ext::WriteMaxStreamDataFrame, max_streams::ext::WriteMaxStreamsFrame,
        new_connection_id::ext::WriteNewConnectionIdFrame,
        path_challenge::ext::WritePathChallengeFrame, path_response::ext::WritePathResponseFrame,
        reset_stream::ext::WriteResetStreamFrame,
        retire_connection_id::ext::WriteRetireConnectionIdFrame,
        stop_sending::ext::WriteStopSendingFrame,
        stream_data_blocked::ext::WriteStreamDataBlockedFrame,
        streams_blocked::ext::WriteStreamsBlockedFrame,
    };

    pub use super::{
        ack::ext::WriteAckFrame, connection_close::ext::WriteConnectionCloseFrame,
        crypto::ext::WriteCryptoFrame, padding::ext::WritePaddingFrame, ping::ext::WritePingFrame,
        stream::ext::WriteStreamFrame,
    };

    pub trait WriteFrame<F> {
        fn put_frame(&mut self, frame: &F);
    }

    pub trait WriteDataFrame<D> {
        fn put_frame_with_data(&mut self, frame: &D, data: &[u8]);
    }

    impl<T: bytes::BufMut> WriteFrame<ConnFrame> for T {
        fn put_frame(&mut self, frame: &ConnFrame) {
            match frame {
                ConnFrame::Close(frame) => self.put_connection_close_frame(frame),
                ConnFrame::NewToken(frame) => self.put_new_token_frame(frame),
                ConnFrame::MaxData(frame) => self.put_max_data_frame(frame),
                ConnFrame::DataBlocked(frame) => self.put_data_blocked_frame(frame),
                ConnFrame::NewConnectionId(frame) => self.put_new_connection_id_frame(frame),
                ConnFrame::RetireConnectionId(frame) => self.put_retire_connection_id_frame(frame),
                ConnFrame::HandshakeDone(_) => self.put_handshake_done_frame(),
            }
        }
    }

    impl<T: bytes::BufMut> WriteFrame<StreamInfoFrame> for T {
        fn put_frame(&mut self, frame: &StreamInfoFrame) {
            match frame {
                StreamInfoFrame::ResetStream(frame) => self.put_reset_stream_frame(frame),
                StreamInfoFrame::StopSending(frame) => self.put_stop_sending_frame(frame),
                StreamInfoFrame::MaxStreamData(frame) => self.put_max_stream_data_frame(frame),
                StreamInfoFrame::MaxStreams(frame) => self.put_max_streams_frame(frame),
                StreamInfoFrame::StreamDataBlocked(frame) => {
                    self.put_stream_data_blocked_frame(frame)
                }
                StreamInfoFrame::StreamsBlocked(frame) => self.put_streams_blocked_frame(frame),
            }
        }
    }

    impl<T: bytes::BufMut> WriteFrame<PathFrame> for T {
        fn put_frame(&mut self, frame: &PathFrame) {
            match frame {
                PathFrame::Challenge(frame) => self.put_path_challenge_frame(frame),
                PathFrame::Response(frame) => self.put_path_response_frame(frame),
            }
        }
    }

    impl<T: bytes::BufMut> WriteFrame<PureFrame> for T {
        fn put_frame(&mut self, frame: &PureFrame) {
            match frame {
                PureFrame::Conn(frame) => self.put_frame(frame),
                PureFrame::Stream(frame) => self.put_frame(frame),
                PureFrame::Path(frame) => self.put_frame(frame),
            }
        }
    }

    impl<T: bytes::BufMut> WriteDataFrame<CryptoFrame> for T {
        fn put_frame_with_data(&mut self, frame: &CryptoFrame, data: &[u8]) {
            self.put_crypto_frame(frame, data);
        }
    }

    impl<T: bytes::BufMut> WriteDataFrame<StreamFrame> for T {
        fn put_frame_with_data(&mut self, frame: &StreamFrame, data: &[u8]) {
            self.put_stream_frame(frame, data);
        }
    }

    impl<T: bytes::BufMut> WriteDataFrame<DataFrame> for T {
        fn put_frame_with_data(&mut self, frame: &DataFrame, data: &[u8]) {
            match frame {
                DataFrame::Crypto(frame) => self.put_crypto_frame(frame, data),
                DataFrame::Stream(frame) => self.put_stream_frame(frame, data),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
