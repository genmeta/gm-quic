use crate::{
    cid::{ConnectionId, ResetToken},
    varint::VarInt,
};

use super::FrameType;

pub(super) const NEW_CONNECTION_ID_FRAME_TYPE: u8 = 0x18;

#[derive(Debug, Copy, Clone)]
pub struct NewConnectionId {
    pub(crate) sequence: VarInt,
    pub(crate) retire_prior_to: VarInt,
    pub(crate) id: ConnectionId,
    pub(crate) reset_token: ResetToken,
}

impl super::BeFrame for NewConnectionId {
    fn frame_type(&self) -> FrameType {
        super::FrameType::NewConnectionId
    }
}

pub(super) mod ext {
    use nom::bytes::complete::take;
    use nom::number::complete::be_u8;

    use crate::{
        cid::{ResetToken, RESET_TOKEN_SIZE},
        varint::ext::{be_varint, BufMutExt},
    };

    use super::NewConnectionId;

    pub fn be_new_connection_id_frame(input: &[u8]) -> nom::IResult<&[u8], NewConnectionId> {
        let (remain, sequence) = be_varint(input)?;
        let (remain, retire_prior_to) = be_varint(remain)?;
        // todo: error type
        if retire_prior_to > sequence {
            return Err(nom::Err::Error(nom::error::make_error(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }
        let (reamin, length) = be_u8(remain)?;
        if length > crate::cid::MAX_CID_SIZE as u8 || length == 0 {
            return Err(nom::Err::Error(nom::error::make_error(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }
        let (remain, id) = super::ConnectionId::from_buf(reamin, length as usize)?;
        let (remain, reset_token) = take(RESET_TOKEN_SIZE)(remain)?;
        Ok((
            remain,
            NewConnectionId {
                sequence,
                retire_prior_to,
                id,
                reset_token: ResetToken::new_with(reset_token),
            },
        ))
    }

    pub trait WriteNewConnectionIdFrame {
        fn put_new_connection_id_frame(&mut self, frame: &NewConnectionId);
    }

    impl<T: bytes::BufMut> WriteNewConnectionIdFrame for T {
        fn put_new_connection_id_frame(&mut self, frame: &NewConnectionId) {
            self.put_u8(super::NEW_CONNECTION_ID_FRAME_TYPE);
            self.put_varint(&frame.sequence);
            self.put_varint(&frame.retire_prior_to);
            self.put_u8(frame.id.len() as u8);
            self.put_slice(&frame.id);
            self.put_slice(&frame.reset_token);
        }
    }
}
