use std::time::Duration;

use bytes::Bytes;
use nom::Parser;

use crate::{
    cid::{ConnectionId, WriteConnectionId, be_connection_id_with_len},
    error::{ErrorKind, QuicError},
    frame::FrameType,
    param::{
        core::{
            ClientParameters, ParameterId, ParameterType, ParameterValue, Parameters,
            ServerParameters,
        },
        prefered_address::{PreferredAddress, WirtePreferredAddress, be_preferred_address},
    },
    token::{ResetToken, WriteResetToken, be_reset_token},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// Parse the parameter id from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub(super) fn be_parameter_id(input: &[u8]) -> nom::IResult<&[u8], Result<ParameterId, VarInt>> {
    be_varint(input).map(|(remain, id)| (remain, id.try_into()))
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly
/// to write the parameter id.
pub trait WriteParameterId: bytes::BufMut {
    /// Write the parameter id to the buffer.
    fn put_parameter_id(&mut self, param_id: ParameterId);
}

impl<T: bytes::BufMut> WriteParameterId for T {
    fn put_parameter_id(&mut self, param_id: ParameterId) {
        self.put_varint(&VarInt::from(param_id));
    }
}

// 未知ID返回错误（ID，len），qbase解析忽略未知ID
pub fn be_parameter(
    input: &[u8],
) -> nom::IResult<&[u8], (Result<ParameterId, VarInt>, ParameterValue)> {
    use nom::{bytes::streaming::take, combinator::map};

    let (remain, id) = be_parameter_id(input)?;
    let (remain, len) = be_varint(remain)?;
    let (remain, value) = match id.map(|id| id.value_type()).unwrap_or(ParameterType::Bytes) {
        ParameterType::VarInt => map(be_varint, ParameterValue::VarInt).parse(remain)?,
        ParameterType::Flag => (remain, ParameterValue::Enabled),
        ParameterType::Bytes => map(take(len.into_inner() as usize), |bytes| {
            Bytes::copy_from_slice(bytes).into()
        })
        .parse(remain)?,
        ParameterType::Duration => map(be_varint, |varint| {
            let millis = varint.into_inner();
            Duration::from_millis(millis).into()
        })
        .parse(remain)?,
        ParameterType::ResetToken => {
            map(be_reset_token, ParameterValue::ResetToken).parse(remain)?
        }
        ParameterType::ConnectionId => {
            let parser = |input| be_connection_id_with_len(input, len.into_inner() as usize);
            map(parser, ParameterValue::ConnectionId).parse(remain)?
        }
        ParameterType::PreferredAddress => {
            map(be_preferred_address, ParameterValue::PreferredAddress).parse(remain)?
        }
    };

    Ok((remain, (id, value)))
}

// A trait for writing parameters to the buffer.
pub trait WriteParameter {
    fn put_bytes_parameter(&mut self, id: ParameterId, bytes: &Bytes);

    fn put_cid_parameter(&mut self, id: ParameterId, cid: &ConnectionId);

    fn put_duration_parameter(&mut self, id: ParameterId, dur: &Duration) {
        let value = VarInt::from_u128(dur.as_millis()).expect("Duration too large");
        self.put_varint_parameter(id, &value);
    }

    fn put_flag_parameter(&mut self, id: ParameterId);

    fn put_preferred_address_parameter(&mut self, id: ParameterId, addr: &PreferredAddress);

    fn put_reset_token_parameter(&mut self, id: ParameterId, token: &ResetToken);

    fn put_varint_parameter(&mut self, id: ParameterId, value: &VarInt);

    fn put_parameter(&mut self, id: ParameterId, value: &ParameterValue) {
        match value {
            ParameterValue::Bytes(bytes) => self.put_bytes_parameter(id, bytes),
            ParameterValue::ConnectionId(cid) => self.put_cid_parameter(id, cid),
            ParameterValue::Duration(dur) => self.put_duration_parameter(id, dur),
            ParameterValue::Enabled => self.put_flag_parameter(id),
            ParameterValue::PreferredAddress(addr) => {
                self.put_preferred_address_parameter(id, addr)
            }
            ParameterValue::ResetToken(token) => self.put_reset_token_parameter(id, token),
            ParameterValue::VarInt(varint) => self.put_varint_parameter(id, varint),
        }
    }
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly
/// to write parameters.
impl<T: bytes::BufMut> WriteParameter for T {
    fn put_bytes_parameter(&mut self, id: ParameterId, bytes: &Bytes) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::try_from(bytes.len()).expect("param too large"));
        self.put_slice(bytes);
    }

    fn put_cid_parameter(&mut self, id: ParameterId, cid: &ConnectionId) {
        self.put_parameter_id(id);
        self.put_connection_id(cid);
    }

    fn put_flag_parameter(&mut self, id: ParameterId) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::from_u32(0));
    }

    fn put_preferred_address_parameter(&mut self, id: ParameterId, addr: &PreferredAddress) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::try_from(addr.encoding_size()).expect("param too large"));
        self.put_preferred_address(addr);
    }

    fn put_reset_token_parameter(&mut self, id: ParameterId, token: &ResetToken) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::try_from(token.encoding_size()).expect("param too large"));
        self.put_reset_token(token);
    }

    fn put_varint_parameter(&mut self, id: ParameterId, value: &VarInt) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::try_from(value.encoding_size()).expect("param too large"));
        self.put_varint(value);
    }
}

pub trait WriteParameters<Role> {
    fn put_parameters(&mut self, params: &Parameters<Role>);
}

impl<Role, T: bytes::BufMut> WriteParameters<Role> for T {
    fn put_parameters(&mut self, params: &Parameters<Role>) {
        for (id, value) in &params.map {
            self.put_parameter(*id, value);
        }
    }
}

fn parameter_error(id: ParameterId, e: impl std::fmt::Display) -> QuicError {
    QuicError::new(
        ErrorKind::TransportParameter,
        FrameType::Crypto.into(),
        format!("parameter 0x{id:x}: {e}"),
    )
}

fn map_nom_error(ne: impl ToString) -> QuicError {
    tracing::error!("   Cause by: parsing parameters");
    QuicError::new(
        ErrorKind::TransportParameter,
        FrameType::Crypto.into(),
        ne.to_string(),
    )
}

fn must_exist(id: ParameterId) -> QuicError {
    tracing::error!("   Cause by: validating parameters");
    parameter_error(id, "must be exist")
}

impl ClientParameters {
    pub fn try_from_bytes(mut buf: &[u8]) -> Result<Self, QuicError> {
        let mut parameters = Self::default();
        while !buf.is_empty() {
            let (id, value);
            (buf, (id, value)) = be_parameter(buf).map_err(map_nom_error)?;
            if let Ok(knwon_id) = id {
                parameters
                    .set(knwon_id, value)
                    .map_err(|e| parameter_error(knwon_id, e))?;
            }
        }
        for id in [ParameterId::InitialSourceConnectionId] {
            if !parameters.contains(id) {
                return Err(must_exist(id));
            }
        }
        Ok(parameters)
    }
}

impl ServerParameters {
    pub fn try_from_server_bytes(mut buf: &[u8]) -> Result<Self, QuicError> {
        let mut parameters = Self::default();
        while !buf.is_empty() {
            let (id, value);
            (buf, (id, value)) = be_parameter(buf).map_err(map_nom_error)?;
            if let Ok(knwon_id) = id {
                parameters
                    .set(knwon_id, value)
                    .map_err(|e| parameter_error(knwon_id, e))?;
            }
        }
        for id in [
            ParameterId::InitialSourceConnectionId,
            ParameterId::OriginalDestinationConnectionId,
        ] {
            if !parameters.contains(id) {
                return Err(must_exist(id));
            }
        }
        Ok(parameters)
    }

    pub fn try_from_remembered_bytes(mut buf: &[u8]) -> Result<Self, QuicError> {
        let mut parameters = Self::new();
        while !buf.is_empty() {
            let (id, value);
            (buf, (id, value)) = be_parameter(buf).map_err(map_nom_error)?;
            if let Ok(knwon_id) = id {
                if matches!(
                    knwon_id,
                    ParameterId::OriginalDestinationConnectionId
                        | ParameterId::AckDelayExponent
                        | ParameterId::MaxAckDelay
                        | ParameterId::PreferredAddress
                        | ParameterId::InitialSourceConnectionId
                        | ParameterId::RetrySourceConnectionId
                ) {
                    continue;
                }
                parameters
                    .set(knwon_id, value)
                    .map_err(|e| parameter_error(knwon_id, e))?;
            }
        }
        Ok(parameters)
    }
}
