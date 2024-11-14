use crate::{
    cid::{be_connection_id, ConnectionId, WriteConnectionId},
    token::{be_reset_token, ResetToken, RESET_TOKEN_SIZE},
    varint::{be_varint, VarInt, WriteVarInt},
};

const NEW_CONNECTION_ID_FRAME_TYPE: u8 = 0x18;

/// NEW_CONNECTION_ID frame.
///
/// ```text
/// NEW_CONNECTION_ID Frame {
///   Type (i) = 0x18,
///   Sequence Number (i),
///   Retire Prior To (i),
///   Length (8),
///   Connection ID (8..160),
///   Stateless Reset Token (128),
/// }
/// ```
///
/// See [NEW_CONNECTION_ID Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-new_connection_id-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewConnectionIdFrame {
    pub sequence: VarInt,
    pub retire_prior_to: VarInt,
    pub id: ConnectionId,
    pub reset_token: ResetToken,
}

impl NewConnectionIdFrame {
    pub fn new(cid: ConnectionId, sequence: VarInt, retire_prior_to: VarInt) -> Self {
        let reset_token = ResetToken::random_gen();
        Self {
            sequence,
            retire_prior_to,
            id: cid,
            reset_token,
        }
    }
}

impl super::BeFrame for NewConnectionIdFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::NewConnectionId
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8 + 21 + RESET_TOKEN_SIZE
    }

    fn encoding_size(&self) -> usize {
        1 + self.sequence.encoding_size()
            + self.retire_prior_to.encoding_size()
            + 1
            + self.id.len as usize
            + RESET_TOKEN_SIZE
    }
}

/// Parse a NEW_CONNECTION_ID frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_new_connection_id_frame(input: &[u8]) -> nom::IResult<&[u8], NewConnectionIdFrame> {
    let (remain, sequence) = be_varint(input)?;
    let (remain, retire_prior_to) = be_varint(remain)?;
    // The value in the Retire Prior To field MUST be less than or equal to the value in the
    // Sequence Number field. Receiving a value in the Retire Prior To field that is greater
    // than that in the Sequence Number field MUST be treated as a connection error of type
    // FRAME_ENCODING_ERROR.
    if retire_prior_to > sequence {
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
    let (remain, cid) = be_connection_id(remain)?;
    if cid.len() == 0 {
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }

    let (remain, reset_token) = be_reset_token(remain)?;
    Ok((
        remain,
        NewConnectionIdFrame {
            sequence,
            retire_prior_to,
            id: cid,
            reset_token,
        },
    ))
}

impl super::io::WriteFrame<NewConnectionIdFrame> for &mut [u8] {
    fn put_frame(&mut self, frame: &NewConnectionIdFrame) {
        use bytes::BufMut;
        self.put_u8(NEW_CONNECTION_ID_FRAME_TYPE);
        self.put_varint(&frame.sequence);
        self.put_varint(&frame.retire_prior_to);
        self.put_connection_id(&frame.id);
        self.put_slice(&frame.reset_token);
    }
}
