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
    if cid.is_empty() {
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

impl<T: bytes::BufMut> super::io::WriteFrame<NewConnectionIdFrame> for T {
    fn put_frame(&mut self, frame: &NewConnectionIdFrame) {
        self.put_u8(NEW_CONNECTION_ID_FRAME_TYPE);
        self.put_varint(&frame.sequence);
        self.put_varint(&frame.retire_prior_to);
        self.put_connection_id(&frame.id);
        self.put_slice(&frame.reset_token);
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};

    use super::*;
    use crate::frame::{io::WriteFrame, BeFrame, FrameType};

    #[test]
    fn test_new_connection_id_frame() {
        let new_cid_frame = NewConnectionIdFrame::new(
            ConnectionId::from_slice(&[1, 2, 3, 4][..]),
            VarInt::from_u32(1),
            VarInt::from_u32(0),
        );
        assert_eq!(new_cid_frame.sequence, VarInt::from_u32(1));
        assert_eq!(new_cid_frame.retire_prior_to, VarInt::from_u32(0));
        assert_eq!(
            new_cid_frame.id,
            ConnectionId::from_slice(&[1, 2, 3, 4][..])
        );

        assert_eq!(new_cid_frame.frame_type(), FrameType::NewConnectionId);
        assert_eq!(
            new_cid_frame.max_encoding_size(),
            1 + 8 + 8 + 21 + RESET_TOKEN_SIZE
        );
        assert_eq!(new_cid_frame.encoding_size(), 1 + 1 + 1 + 1 + 4 + 16);
    }

    #[test]
    fn test_frame_parsing() {
        let mut buf = BytesMut::new();
        let original_cid = ConnectionId::from_slice(&[1, 2, 3, 4][..]);
        let original_frame =
            NewConnectionIdFrame::new(original_cid, VarInt::from_u32(1), VarInt::from_u32(0));

        // Write frame to buffer
        buf.put_frame(&original_frame);

        // Skip frame type byte
        let (_, parsed_frame) = be_new_connection_id_frame(&buf[1..]).unwrap();

        assert_eq!(parsed_frame.sequence, original_frame.sequence);
        assert_eq!(parsed_frame.retire_prior_to, original_frame.retire_prior_to);
        assert_eq!(parsed_frame.id, original_frame.id);
        assert_eq!(parsed_frame.reset_token, original_frame.reset_token);
    }

    #[test]
    fn test_invalid_retire_prior_to() {
        let mut buf = BytesMut::new();
        buf.put_u8(NEW_CONNECTION_ID_FRAME_TYPE);
        buf.put_varint(&VarInt::from_u32(1)); // sequence
        buf.put_varint(&VarInt::from_u32(2)); // retire_prior_to > sequence

        assert!(be_new_connection_id_frame(&buf[1..]).is_err());
    }

    #[test]
    fn test_zero_length_connection_id() {
        let mut buf = BytesMut::new();
        buf.put_u8(NEW_CONNECTION_ID_FRAME_TYPE);
        buf.put_varint(&VarInt::from_u32(1));
        buf.put_varint(&VarInt::from_u32(0));
        buf.put_u8(0); // zero length CID

        assert!(be_new_connection_id_frame(&buf[1..]).is_err());
    }
}
