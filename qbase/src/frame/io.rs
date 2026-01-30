use bytes::Bytes;

use super::{
    ack::ack_frame_with_ecn, connection_close::connection_close_frame_at_layer,
    crypto::be_crypto_frame, data_blocked::be_data_blocked_frame,
    datagram::datagram_frame_with_flag, max_data::be_max_data_frame,
    max_stream_data::be_max_stream_data_frame, max_streams::max_streams_frame_with_dir,
    new_connection_id::be_new_connection_id_frame, new_token::be_new_token_frame,
    path_challenge::be_path_challenge_frame, path_response::be_path_response_frame,
    reset_stream::be_reset_stream_frame, retire_connection_id::be_retire_connection_id_frame,
    stop_sending::be_stop_sending_frame, stream::stream_frame_with_flag,
    stream_data_blocked::be_stream_data_blocked_frame,
    streams_blocked::streams_blocked_frame_with_dir, *,
};
use crate::util::ContinuousData;

/// Return a parser for a complete frame from the raw bytes with the given type,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
///
/// Some frames like [`StreamFrame`] and [`CryptoFrame`] have a data body,
/// which use `bytes::Bytes` to store.
fn complete_frame(
    frame_type: FrameType,
    raw: Bytes,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], Frame> {
    use nom::{Parser, combinator::map};
    move |input: &[u8]| match frame_type {
        FrameType::Padding => Ok((input, Frame::Padding(PaddingFrame))),
        FrameType::Ping => Ok((input, Frame::Ping(PingFrame))),
        FrameType::ConnectionClose(layer) => {
            map(connection_close_frame_at_layer(layer), Frame::Close).parse(input)
        }
        FrameType::NewConnectionId => {
            map(be_new_connection_id_frame, Frame::NewConnectionId).parse(input)
        }
        FrameType::RetireConnectionId => {
            map(be_retire_connection_id_frame, Frame::RetireConnectionId).parse(input)
        }
        FrameType::DataBlocked => map(be_data_blocked_frame, Frame::DataBlocked).parse(input),
        FrameType::MaxData => map(be_max_data_frame, Frame::MaxData).parse(input),
        FrameType::PathChallenge => map(be_path_challenge_frame, Frame::Challenge).parse(input),
        FrameType::PathResponse => map(be_path_response_frame, Frame::Response).parse(input),
        FrameType::HandshakeDone => Ok((input, Frame::HandshakeDone(HandshakeDoneFrame))),
        FrameType::NewToken => map(be_new_token_frame, Frame::NewToken).parse(input),
        FrameType::Ack(ecn) => map(ack_frame_with_ecn(ecn), Frame::Ack).parse(input),
        FrameType::ResetStream => {
            map(be_reset_stream_frame, |f| Frame::StreamCtl(f.into())).parse(input)
        }
        FrameType::StopSending => {
            map(be_stop_sending_frame, |f| Frame::StreamCtl(f.into())).parse(input)
        }
        FrameType::MaxStreamData => {
            map(be_max_stream_data_frame, |f| Frame::StreamCtl(f.into())).parse(input)
        }
        FrameType::MaxStreams(dir) => map(max_streams_frame_with_dir(dir), |f| {
            Frame::StreamCtl(f.into())
        })
        .parse(input),
        FrameType::StreamsBlocked(dir) => map(streams_blocked_frame_with_dir(dir), |f| {
            Frame::StreamCtl(f.into())
        })
        .parse(input),
        FrameType::StreamDataBlocked => {
            map(be_stream_data_blocked_frame, |f| Frame::StreamCtl(f.into())).parse(input)
        }
        FrameType::Crypto => {
            let (input, frame) = be_crypto_frame(input)?;
            let start = raw.len() - input.len();
            let len = frame.len() as usize;
            if input.len() < len {
                Err(nom::Err::Incomplete(nom::Needed::new(len - input.len())))
            } else {
                let data = raw.slice(start..start + len);
                Ok((&input[len..], Frame::Crypto(frame, data)))
            }
        }
        FrameType::Stream(flags) => {
            let (input, frame) = stream_frame_with_flag(flags)(input)?;
            let start = raw.len() - input.len();
            let len = frame.len();
            if input.len() < len {
                Err(nom::Err::Incomplete(nom::Needed::new(len - input.len())))
            } else {
                let data = raw.slice(start..start + len);
                Ok((&input[len..], Frame::Stream(frame, data)))
            }
        }
        FrameType::Datagram(with_len) => {
            let (input, frame) = datagram_frame_with_flag(with_len)(input)?;
            let start = raw.len() - input.len();
            match frame.encode_len() {
                true if frame.len().into_inner() > input.len() as u64 => Err(nom::Err::Incomplete(
                    nom::Needed::new((frame.len().into_inner() - input.len() as u64) as usize),
                )),
                true => {
                    let data = raw.slice(start..start + frame.len().into_inner() as usize);
                    Ok((
                        &input[frame.len().into_inner() as usize..],
                        Frame::Datagram(frame, data),
                    ))
                }
                false => {
                    let data = raw.slice(start..);
                    Ok((&[], Frame::Datagram(frame, data)))
                }
            }
        }
    }
}

/// Parse a frame type from the raw bytes, [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_frame(raw: &Bytes, packet_type: Type) -> Result<(usize, Frame, FrameType), Error> {
    let input = raw.as_ref();
    let (remain, frame_type) = be_frame_type(input)?;
    if !frame_type.belongs_to(packet_type) {
        return Err(Error::WrongType(frame_type, packet_type));
    }

    let (remain, frame) = complete_frame(frame_type, raw.clone())(remain).map_err(|e| match e {
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
    Ok((input.len() - remain.len(), frame, frame_type))
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly
/// to write all kinds of frames.
pub trait WriteFrame<F>: bytes::BufMut {
    /// Write a frame to the buffer.
    fn put_frame(&mut self, frame: &F);
}

impl<B: BufMut, D: ContinuousData> WriteFrame<Frame<D>> for B
where
    D: ContinuousData,
    B: BufMut + ?Sized,
    for<'b> &'b mut B: crate::util::WriteData<D>,
{
    fn put_frame(&mut self, frame: &Frame<D>) {
        let mut buf = self;
        match frame {
            Frame::Padding(f) => <&mut B as WriteFrame<PaddingFrame>>::put_frame(&mut buf, f),
            Frame::Ping(f) => <&mut B as WriteFrame<PingFrame>>::put_frame(&mut buf, f),
            Frame::Ack(f) => <&mut B as WriteFrame<AckFrame>>::put_frame(&mut buf, f),
            Frame::Close(f) => <&mut B as WriteFrame<ConnectionCloseFrame>>::put_frame(&mut buf, f),
            Frame::NewToken(f) => <&mut B as WriteFrame<NewTokenFrame>>::put_frame(&mut buf, f),
            Frame::MaxData(f) => <&mut B as WriteFrame<MaxDataFrame>>::put_frame(&mut buf, f),
            Frame::DataBlocked(f) => {
                <&mut B as WriteFrame<DataBlockedFrame>>::put_frame(&mut buf, f)
            }
            Frame::NewConnectionId(f) => {
                <&mut B as WriteFrame<NewConnectionIdFrame>>::put_frame(&mut buf, f)
            }
            Frame::RetireConnectionId(f) => {
                <&mut B as WriteFrame<RetireConnectionIdFrame>>::put_frame(&mut buf, f)
            }
            Frame::HandshakeDone(f) => {
                <&mut B as WriteFrame<HandshakeDoneFrame>>::put_frame(&mut buf, f)
            }
            Frame::Challenge(f) => {
                <&mut B as WriteFrame<PathChallengeFrame>>::put_frame(&mut buf, f)
            }
            Frame::Response(f) => <&mut B as WriteFrame<PathResponseFrame>>::put_frame(&mut buf, f),
            Frame::StreamCtl(f) => <&mut B as WriteFrame<StreamCtlFrame>>::put_frame(&mut buf, f),
            Frame::Stream(f, d) => buf.put_data_frame(f, d),
            Frame::Crypto(f, d) => buf.put_data_frame(f, d),
            Frame::Datagram(f, d) => buf.put_data_frame(f, d),
        }
    }
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly
/// to write frame with data.
pub trait WriteDataFrame<F, D: ContinuousData>: bytes::BufMut {
    /// Write a frame and its data to the buffer.
    fn put_data_frame(&mut self, frame: &F, data: &D);
}
