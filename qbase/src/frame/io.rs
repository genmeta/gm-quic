use bytes::Bytes;

use super::{
    ack::ack_frame_with_flag, connection_close::connection_close_frame_at_layer,
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

/// Some frames like `STREAM` and `CRYPTO` have a data body, which use `bytes::Bytes` to store.
fn complete_frame(
    frame_type: FrameType,
    raw: Bytes,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], Frame> {
    use nom::combinator::map;
    move |input: &[u8]| match frame_type {
        FrameType::Padding => Ok((input, Frame::Padding(PaddingFrame))),
        FrameType::Ping => Ok((input, Frame::Ping(PingFrame))),
        FrameType::ConnectionClose(layer) => {
            map(connection_close_frame_at_layer(layer), Frame::Close)(input)
        }
        FrameType::NewConnectionId => {
            map(be_new_connection_id_frame, Frame::NewConnectionId)(input)
        }
        FrameType::RetireConnectionId => {
            map(be_retire_connection_id_frame, Frame::RetireConnectionId)(input)
        }
        FrameType::DataBlocked => map(be_data_blocked_frame, Frame::DataBlocked)(input),
        FrameType::MaxData => map(be_max_data_frame, Frame::MaxData)(input),
        FrameType::PathChallenge => map(be_path_challenge_frame, Frame::Challenge)(input),
        FrameType::PathResponse => map(be_path_response_frame, Frame::Response)(input),
        FrameType::HandshakeDone => Ok((input, Frame::HandshakeDone(HandshakeDoneFrame))),
        FrameType::NewToken => map(be_new_token_frame, Frame::NewToken)(input),
        FrameType::Ack(ecn) => map(ack_frame_with_flag(ecn), Frame::Ack)(input),
        FrameType::ResetStream => map(be_reset_stream_frame, |f| Frame::Stream(f.into()))(input),
        FrameType::StopSending => map(be_stop_sending_frame, |f| Frame::Stream(f.into()))(input),
        FrameType::MaxStreamData => {
            map(be_max_stream_data_frame, |f| Frame::Stream(f.into()))(input)
        }
        FrameType::MaxStreams(dir) => {
            map(max_streams_frame_with_dir(dir), |f| Frame::Stream(f.into()))(input)
        }
        FrameType::StreamsBlocked(dir) => map(streams_blocked_frame_with_dir(dir), |f| {
            Frame::Stream(f.into())
        })(input),
        FrameType::StreamDataBlocked => {
            map(be_stream_data_blocked_frame, |f| Frame::Stream(f.into()))(input)
        }
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
            let len = frame.len();
            if input.len() < len {
                Err(nom::Err::Incomplete(nom::Needed::new(len - input.len())))
            } else {
                let data = raw.slice(start..start + len);
                Ok((&input[len..], Frame::Data(DataFrame::Stream(frame), data)))
            }
        }
        FrameType::Datagram(with_len) => {
            let (input, frame) = datagram_frame_with_flag(with_len)(input)?;
            let start = raw.len() - input.len();
            match frame.length.map(|len| len.into_inner() as usize) {
                Some(len) if len > input.len() => {
                    Err(nom::Err::Incomplete(nom::Needed::new(len - input.len())))
                }
                Some(len) => {
                    let data = raw.slice(start..start + len);
                    Ok((&input[len..], Frame::Datagram(frame, data)))
                }
                None => {
                    let data = raw.slice(start..);
                    Ok((&[], Frame::Datagram(frame, data)))
                }
            }
        }
    }
}

pub fn be_frame(raw: &Bytes, packet_type: Type) -> Result<(usize, Frame, bool), Error> {
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
    Ok((
        input.len() - remain.len(),
        frame,
        frame_type.is_ack_eliciting(),
    ))
}

pub use super::{
    ack::WriteAckFrame, connection_close::WriteConnectionCloseFrame, crypto::WriteCryptoFrame,
    data_blocked::WriteDataBlockedFrame, datagram::WriteDatagramFrame,
    handshake_done::WriteHandshakeDoneFrame, max_data::WriteMaxDataFrame,
    new_connection_id::WriteNewConnectionIdFrame, new_token::WriteNewTokenFrame,
    padding::WritePaddingFrame, path_challenge::WritePathChallengeFrame,
    path_response::WritePathResponseFrame, ping::WritePingFrame,
    retire_connection_id::WriteRetireConnectionIdFrame, stream::WriteStreamFrame,
};
use super::{
    max_stream_data::WriteMaxStreamDataFrame, max_streams::WriteMaxStreamsFrame,
    reset_stream::WriteResetStreamFrame, stop_sending::WriteStopSendingFrame,
    stream_data_blocked::WriteStreamDataBlockedFrame, streams_blocked::WriteStreamsBlockedFrame,
};

pub trait WriteFrame<F> {
    fn put_frame(&mut self, frame: &F);
}

impl<T: bytes::BufMut> WriteFrame<StreamCtlFrame> for T {
    fn put_frame(&mut self, frame: &StreamCtlFrame) {
        match frame {
            StreamCtlFrame::ResetStream(frame) => self.put_reset_stream_frame(frame),
            StreamCtlFrame::StopSending(frame) => self.put_stop_sending_frame(frame),
            StreamCtlFrame::MaxStreamData(frame) => self.put_max_stream_data_frame(frame),
            StreamCtlFrame::MaxStreams(frame) => self.put_max_streams_frame(frame),
            StreamCtlFrame::StreamDataBlocked(frame) => self.put_stream_data_blocked_frame(frame),
            StreamCtlFrame::StreamsBlocked(frame) => self.put_streams_blocked_frame(frame),
        }
    }
}
