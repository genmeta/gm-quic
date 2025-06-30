use std::time::Duration;

use bytes::Bytes;
use nom::{Parser, multi::length_data};

use crate::{
    cid::{ConnectionId, WriteConnectionId},
    error::QuicError,
    param::{
        core::{ParameterId, ParameterValue, ParameterValueType, Parameters, ServerParameters},
        error::Error,
        prefered_address::{PreferredAddress, WirtePreferredAddress, be_preferred_address},
    },
    role::{IntoRole, RequiredParameters, Role},
    token::{ResetToken, WriteResetToken, be_reset_token},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// Parse the parameter id from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub(super) fn be_parameter_id_of_role(
    input: &[u8],
    role: Role,
) -> nom::IResult<&[u8], ParameterId, Error> {
    let (remain, param_id) = crate::varint::be_varint(input).map_err(|_| {
        nom::Err::Error(Error::IncompleteParameterId(format!(
            "incomplete frame type from input: {input:?}"
        )))
    })?;
    let param_id = ParameterId::try_from(param_id).map_err(nom::Err::Error)?;
    param_id.belong_to(role).map_err(nom::Err::Error)?;
    Ok((remain, param_id))
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
pub fn be_parameter_of_role(
    input: &[u8],
    role: Role,
) -> nom::IResult<&[u8], (ParameterId, ParameterValue), Error> {
    use nom::combinator::map;

    let (remain, param_id) = be_parameter_id_of_role(input, role)?;
    let (remain, data) = length_data(be_varint).parse(remain).map_err(|_| {
        nom::Err::Error(Error::IncompleteParameterId(format!(
            "incomplete frame type from input: {input:?}"
        )))
    })?;
    let incomplete_value_error = |id: ParameterId, data: &[u8]| {
        nom::Err::Error(Error::IncompleteValue(
            id,
            format!("incomplete frame type from input: {data:?}"),
        ))
    };
    let (_, param_value) = match param_id.value_type() {
        ParameterValueType::VarInt => map(be_varint, ParameterValue::VarInt)
            .parse(data)
            .map_err(|_| incomplete_value_error(param_id, data))?,
        ParameterValueType::Boolean => (remain, ParameterValue::True),
        ParameterValueType::Bytes => (remain, ParameterValue::Bytes(Bytes::copy_from_slice(data))),
        ParameterValueType::Duration => {
            map(be_varint, |v| Duration::from_millis(v.into_inner()).into())
                .parse(data)
                .map_err(|_| incomplete_value_error(param_id, data))?
        }
        ParameterValueType::ResetToken => map(be_reset_token, ParameterValue::ResetToken)
            .parse(data)
            .map_err(|_| incomplete_value_error(param_id, data))?,
        ParameterValueType::ConnectionId => (
            remain,
            ParameterValue::ConnectionId(ConnectionId::from_slice(data)),
        ),
        ParameterValueType::PreferredAddress => {
            map(be_preferred_address, ParameterValue::PreferredAddress)
                .parse(data)
                .map_err(|_| incomplete_value_error(param_id, data))?
        }
    };

    Ok((remain, (param_id, param_value)))
}

// A trait for writing parameters to the buffer.
pub trait WriteParameter {
    fn put_bytes_parameter(&mut self, id: ParameterId, bytes: &Bytes);

    fn put_cid_parameter(&mut self, id: ParameterId, cid: &ConnectionId);

    fn put_duration_parameter(&mut self, id: ParameterId, dur: &Duration) {
        let value = VarInt::from_u128(dur.as_millis()).expect("Duration too large");
        self.put_varint_parameter(id, &value);
    }

    fn put_bool_parameter(&mut self, id: ParameterId);

    fn put_preferred_address_parameter(&mut self, id: ParameterId, addr: &PreferredAddress);

    fn put_reset_token_parameter(&mut self, id: ParameterId, token: &ResetToken);

    fn put_varint_parameter(&mut self, id: ParameterId, value: &VarInt);

    fn put_parameter(&mut self, id: ParameterId, value: &ParameterValue) {
        match value {
            ParameterValue::Bytes(bytes) => self.put_bytes_parameter(id, bytes),
            ParameterValue::ConnectionId(cid) => self.put_cid_parameter(id, cid),
            ParameterValue::Duration(dur) => self.put_duration_parameter(id, dur),
            ParameterValue::True => self.put_bool_parameter(id),
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

    fn put_bool_parameter(&mut self, id: ParameterId) {
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

impl<R: IntoRole + RequiredParameters + Default> Parameters<R> {
    pub fn parse_from_bytes(mut buf: &[u8]) -> Result<Self, QuicError> {
        let mut parameters = Self::default();
        while !buf.is_empty() {
            let (param_id, param_value);
            (buf, (param_id, param_value)) = match be_parameter_of_role(buf, R::into_role()) {
                Ok((remain, pair)) => (remain, pair),
                Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
                    if let Error::UnknownParameterId(varint) = e {
                        tracing::warn!("Unknown parameter id: {varint}");
                        // Ignore unknown parameters
                        continue;
                    }
                    return Err(e.into());
                }
                Err(nom::Err::Incomplete(_)) => {
                    unreachable!(
                        "Because the parsing of QUIC packets and frames is not stream-based."
                    );
                }
            };
            parameters.set(param_id, param_value)?;
        }
        for id in R::required_parameters() {
            if !parameters.contains(id) {
                return Err(Error::LackParameterId(R::into_role(), id).into());
            }
        }
        Ok(parameters)
    }
}

impl ServerParameters {
    pub fn try_from_remembered_bytes(mut buf: &[u8]) -> Result<Self, QuicError> {
        let mut parameters = Self::new();
        while !buf.is_empty() {
            let (param_id, param_value);
            (buf, (param_id, param_value)) = match be_parameter_of_role(buf, Role::Server) {
                Ok((remain, pair)) => (remain, pair),
                Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
                    return Err(e.into());
                }
                Err(nom::Err::Incomplete(_)) => {
                    unreachable!(
                        "Because the parsing of QUIC packets and frames is not stream-based."
                    );
                }
            };
            parameters.set(param_id, param_value)?;
        }
        Ok(parameters)
    }
}
