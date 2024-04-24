// This folder defines all the frames, including their parsing and packaging processes.

mod ack;
mod crypto;
mod data_blocked;
mod max_data;
mod max_stream_data;
mod max_streams;
mod padding;
mod ping;
mod reset_stream;
mod stop_sending;
mod stream;
mod stream_data_blocked;
mod streams_blocked;

// re-export for convenience
pub use ack::AckFrame;
pub use crypto::CryptoFrame;
pub use data_blocked::DataBlockedFrame;
pub use max_data::MaxDataFrame;
pub use max_stream_data::MaxStreamDataFrame;
pub use max_streams::MaxStreamsFrame;
pub use padding::PaddingFrame;
pub use ping::PingFrame;
pub use reset_stream::ResetStreamFrame;
pub use stop_sending::StopSendingFrame;
pub use stream::StreamFrame;
pub use stream_data_blocked::StreamDataBlockedFrame;
pub use streams_blocked::StreamsBlockedFrame;

use std::ops::RangeInclusive;

use bytes::Bytes;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FrameType {
    Padding,
    Ping,
    DataBlocked,
    MaxData,
    MaxStreamData,
    MaxStreams(u8),
    StreamDataBlocked,
    Ack(u8),
    Stream(u8),
    ResetStream,
    StopSending,
    Crypto,
    StreamsBlocked(u8),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidFrameType(u8);

impl TryFrom<u8> for FrameType {
    type Error = InvalidFrameType;

    fn try_from(frame_type: u8) -> Result<Self, Self::Error> {
        Ok(match frame_type {
            padding::PADDING_FRAME_TYPE => FrameType::Padding,
            ping::PING_FRAME_TYPE => FrameType::Ping,
            0b10 | 0b11 => FrameType::Ack(frame_type & 0b1),
            reset_stream::RESET_STREAM_FRAME_TYPE => FrameType::ResetStream,
            crypto::CRYPTO_FRAME_TYPE => FrameType::Crypto,
            data_blocked::DATA_BLOCKED_FRAME_TYPE => FrameType::DataBlocked,
            max_data::MAX_DATA_FRAME_TYPE => FrameType::MaxData,
            max_stream_data::MAX_STREAM_DATA_FRAME_TYPE => FrameType::MaxStreamData,
            0b10010 | 0b10011 => FrameType::MaxStreams(frame_type & 0b1),
            stop_sending::STOP_SENDING_FRAME_TYPE => FrameType::StopSending,
            stream_data_blocked::STREAM_DATA_BLOCKED_FRAME_TYPE => FrameType::StreamDataBlocked,
            0b1000..=0b1111 => FrameType::Stream(frame_type & 0b111),
            0b10110 | 0b10111 => FrameType::StreamsBlocked(frame_type & 0b1),
            _ => return Err(InvalidFrameType(frame_type)),
        })
    }
}

/// 读取的Frame，其中涉及数据体的，得用Bytes来保存，因为数据体可能很大，
/// 放在Frame结构中会很占空间，且有copy的性能开销；如果使用`&[u8]`,
/// 则有生命周期的限制，而数据体实际上要等应用读取后，才可以释放，而并非
/// 在读取解析完一个包后才释放。
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReadFrame {
    Padding,
    Ping,
    Ack(AckFrame),
    Stream(StreamFrame, Bytes),
    ResetStream(ResetStreamFrame),
    Crypto(CryptoFrame, Bytes),
    DataBlocked(DataBlockedFrame),
    MaxData(MaxDataFrame),
    MaxStreamData(MaxStreamDataFrame),
    MaxStreams(MaxStreamsFrame),
    StreamDataBlocked(StreamDataBlockedFrame),
    StopSending(StopSendingFrame),
    StreamsBlocked(StreamsBlockedFrame),
}

/// 写入Frame，仅仅是用于记录，当发送一个Packet时，那该Packet中的帧需要纪律下来，
/// 以便在丢包检测时，决定里面的什么帧丢了，需要重传。
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WriteFrame {
    Padding,
    Ping,
    // 只作记录用，具体的AckFrame不必记录，因为每次AckFrame都要重新从最新的收包记录里生成
    Ack(RangeInclusive<u64>),
    // 数据帧也不包含数据，丢了的话不会原样重传此部分数据，而是向`Sender`标记为丢失
    Stream(StreamFrame),
    ResetStream(ResetStreamFrame),
    Crypto(CryptoFrame),
    DataBlocked(DataBlockedFrame),
    MaxData(MaxDataFrame),
    MaxStreamData(MaxStreamDataFrame),
    StreamDataBlocked(StreamDataBlockedFrame),
    MaxStreams(MaxStreamsFrame),
    StreamsBlocked(StreamsBlockedFrame),
    StopSending(StopSendingFrame),
}

pub mod ext {
    use super::{
        ack::ext::ack_frame_with_flag, crypto::ext::be_crypto_frame,
        data_blocked::ext::be_data_blocked_frame, max_data::ext::be_max_data_frame,
        max_stream_data::ext::be_max_stream_data_frame,
        max_streams::ext::max_streams_frame_with_dir, reset_stream::ext::be_reset_stream_frame,
        stop_sending::ext::be_stop_sending_frame, stream::ext::stream_frame_with_flag,
        stream_data_blocked::ext::be_stream_data_blocked_frame,
        streams_blocked::ext::streams_blocked_frame_with_dir, FrameType, ReadFrame, WriteFrame,
    };

    use bytes::Bytes;
    use nom::{
        combinator::{flat_map, map, map_res},
        error::{Error, ErrorKind},
        Err, IResult,
    };

    fn be_frame_type(input: &[u8]) -> IResult<&[u8], FrameType> {
        use crate::varint::ext::be_varint;
        map_res(be_varint, |frame_type| {
            FrameType::try_from(frame_type.into_inner() as u8)
                .map_err(|_| Error::new(input, ErrorKind::Alt))
        })(input)
    }

    /// Some frames like `STREAM` and `CRYPTO` have a data body, which use `bytes::Bytes` to store.
    fn complete_frame(
        frame_type: FrameType,
        raw: Bytes,
    ) -> impl Fn(&[u8]) -> IResult<&[u8], ReadFrame> {
        move |input: &[u8]| match frame_type {
            FrameType::Padding => Ok((input, ReadFrame::Padding)),
            FrameType::Ping => Ok((input, ReadFrame::Ping)),
            FrameType::Ack(ecn) => map(ack_frame_with_flag(ecn), ReadFrame::Ack)(input),
            FrameType::ResetStream => map(be_reset_stream_frame, ReadFrame::ResetStream)(input),
            FrameType::DataBlocked => map(be_data_blocked_frame, ReadFrame::DataBlocked)(input),
            FrameType::MaxData => map(be_max_data_frame, ReadFrame::MaxData)(input),
            FrameType::StopSending => map(be_stop_sending_frame, ReadFrame::StopSending)(input),
            FrameType::MaxStreamData => {
                map(be_max_stream_data_frame, ReadFrame::MaxStreamData)(input)
            }
            FrameType::MaxStreams(dir) => {
                map(max_streams_frame_with_dir(dir), ReadFrame::MaxStreams)(input)
            }
            FrameType::StreamsBlocked(dir) => map(
                streams_blocked_frame_with_dir(dir),
                ReadFrame::StreamsBlocked,
            )(input),
            FrameType::StreamDataBlocked => {
                map(be_stream_data_blocked_frame, ReadFrame::StreamDataBlocked)(input)
            }
            FrameType::Crypto => {
                let (input, frame) = be_crypto_frame(input)?;
                let start = raw.len() - input.len();
                let len = frame.length.into_inner() as usize;
                if input.len() < len {
                    Err(Err::Incomplete(nom::Needed::new(len - input.len())))
                } else {
                    let data = raw.slice(start..start + len);
                    Ok((&input[len..], ReadFrame::Crypto(frame, data)))
                }
            }
            FrameType::Stream(flag) => {
                let (input, frame) = stream_frame_with_flag(flag)(input)?;
                let start = raw.len() - input.len();
                let len = frame.length;
                if input.len() < len {
                    Err(Err::Incomplete(nom::Needed::new(len - input.len())))
                } else {
                    let data = raw.slice(start..start + len);
                    Ok((&input[len..], ReadFrame::Stream(frame, data)))
                }
            }
        }
    }

    // nom parser for FRAME
    pub fn be_frame<'a>(input: &'a [u8], raw: &Bytes) -> nom::IResult<&'a [u8], ReadFrame> {
        flat_map(be_frame_type, |frame_type| {
            complete_frame(frame_type, raw.clone())
        })(input)
    }

    pub trait BufMutExt {
        fn put_frame(&mut self, frame: &WriteFrame);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_frame(&mut self, frame: &WriteFrame) {
            use super::{
                data_blocked::ext::BufMutExt as DataBlockedBufMutExt,
                max_data::ext::BufMutExt as MaxDataBufMutExt,
                max_stream_data::ext::BufMutExt as MaxStreamDataBufMutExt,
                max_streams::ext::BufMutExt as MaxStreamsBufMutExt,
                padding::ext::BufMutExt as PaddingBufMutExt, ping::ext::BufMutExt as PingBufMutExt,
                reset_stream::ext::BufMutExt as ResetStreamBufMutExt,
                stop_sending::ext::BufMutExt as StopSendingBufMutExt,
                stream_data_blocked::ext::BufMutExt as StreamDataBlockedBufMutExt,
                streams_blocked::ext::BufMutExt as StreamsBlockedBufMutExt,
            };
            match frame {
                WriteFrame::Padding => self.put_padding_frame(),
                WriteFrame::Ping => self.put_ping_frame(),
                WriteFrame::ResetStream(frame) => self.put_reset_stream_frame(frame),
                WriteFrame::DataBlocked(frame) => self.put_data_blocked_frame(frame),
                WriteFrame::MaxData(frame) => self.put_max_data_frame(frame),
                WriteFrame::MaxStreamData(frame) => self.put_max_stream_data_frame(frame),
                WriteFrame::MaxStreams(frame) => self.put_max_streams_frame(frame),
                WriteFrame::StreamsBlocked(frame) => self.put_streams_blocked_frame(frame),
                WriteFrame::StreamDataBlocked(frame) => self.put_stream_data_blocked_frame(frame),
                WriteFrame::StopSending(frame) => self.put_stop_sending_frame(frame),
                WriteFrame::Crypto(_) => {
                    unimplemented!("Cannot write CRYPTO frame directly. Please request the latest data to be sent from crypto buffer.")
                }
                WriteFrame::Stream(_) => {
                    unimplemented!("Cannot write STREAM frame directly. Please request the latest data to be sent from each stream.")
                }
                WriteFrame::Ack(_) => {
                    unimplemented!("Cannot write ACK frame directly. Please regenerate the latest ACK information.")
                }
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
