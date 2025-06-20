use std::{
    collections::HashMap,
    fmt::Debug,
    net::{SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use bytes::Bytes;
use derive_more::{From, TryInto};
use getset::{CopyGetters, MutGetters, Setters};
use nom::Parser;

use crate::{
    cid::{ConnectionId, WriteConnectionId, be_connection_id, be_connection_id_with_len},
    error::{ErrorKind, QuicError},
    frame::FrameType,
    token::{ResetToken, WriteResetToken, be_reset_token},
    varint::{VarInt, WriteVarInt, be_varint},
};

bitflags::bitflags! {
    pub struct ParameterFlags: u8 {
        const NOT_CLIENT = 1 << 0;
        const NOT_SERVER = 1 << 1;
        /// A client MUST NOT use remembered values for the following parameters: ack_delay_exponent, max_ack_delay,
        /// initial_source_connection_id, original_destination_connection_id, preferred_address,
        /// retry_source_connection_id, and stateless_reset_token. The client MUST use the server's new values in the
        /// handshake instead; if the server does not provide new values, the default values are used.
        const NOT_RESUME = 1 << 2;
        const NOT_REDUCE = 1 << 3;
        const CLIENT_REQUIRED = 1 << 4;
        const SERVER_REQUIRED = 1 << 5;
    }
}

impl ParameterFlags {
    pub fn is_client(&self) -> bool {
        !self.contains(ParameterFlags::NOT_CLIENT)
    }

    pub fn is_server(&self) -> bool {
        !self.contains(ParameterFlags::NOT_SERVER)
    }

    pub fn is_resume(&self) -> bool {
        !self.contains(ParameterFlags::NOT_RESUME)
    }
}

macro_rules! parameter_ids {
    /*
    id: ty (cast)? in bound {
        value = id_value,
        (default = default_value)?,
        (flags = flgas_value)?,
    }
    */
    (
        $(#[$meta:meta])*
        $vis:vis enum ParameterId { $(
            $name:ident: $ty:ident $(.$cast:ident() in $bound:expr)? => {
                value = $value:expr
                $(,default = $default:expr)?
                $(,flags = $($flag:ident)|*)?
            }
        ),* $(,)? }
    ) => {
        $(#[$meta])*
        $vis enum ParameterId {
            $($name,)*
            Value(VarInt),
        }

        impl ParameterId{
            pub const KNOWNS: &'static [Self] = &[
                $(ParameterId::$name,)*
            ];

            pub fn flags(&self) -> ParameterFlags {
                match self {
                    $(ParameterId::$name => ParameterFlags::empty() $($(| ParameterFlags::$flag)*)? ,)*
                    ParameterId::Value(_) => ParameterFlags::empty(),
                }
            }

            pub fn default_value(&self) -> Option<ParameterValue> {
                $( $(
                if let ParameterId::$name = self {
                    return Some(ParameterValue::from($default));
                }
                )? )*
                None
            }

            pub fn check_value(&self, value: ParameterValue) -> Result<ParameterValue, QuicError> {
                fn parameter_error(id: ParameterId, ne: impl std::fmt::Display) -> QuicError {
                    QuicError::new(
                        ErrorKind::TransportParameter,
                        FrameType::Crypto.into(),
                        format!("parameter 0x{id:x}: {ne}"),
                    )
                }
                $( $(
                if let ParameterId::$name = self {
                    let value = $ty::try_from(value).map_err(|_| parameter_error(*self, "Invalid parameter value: type unmatch"))?;
                    if !$bound.contains(&value.$cast()) {
                        return Err(parameter_error(*self, format!("Invalid parameter value: out of bound {:?}", $bound)).into());
                    }
                    return Ok(ParameterValue::from(value));
                }
                )? )*
                Ok(value)
            }
        }

        impl From<VarInt> for ParameterId {
            fn from(id: VarInt) -> Self {
                match id.into_inner() {
                    $($value => ParameterId::$name,)*
                    _ => ParameterId::Value(id),
                }
            }
        }

        impl From<ParameterId> for VarInt {
            fn from(id: ParameterId) -> Self {
                match id {
                    $(ParameterId::$name => VarInt::from_u32($value),)*
                    ParameterId::Value(id) => id,
                }
            }
        }
    };
}

parameter_ids! {

/// The parameter id in the transport parameters.
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum ParameterId {
    OriginalDestinationConnectionId: ConnectionId => {
        value = 0x00,
        flags = NOT_CLIENT | NOT_RESUME | SERVER_REQUIRED
    },
    MaxIdleTimeout: Duration => {
        value = 0x01,
        default = Duration::ZERO
    },
    StatelessResetToken: ResetToken => {
        value = 0x02,
        flags = NOT_CLIENT | NOT_RESUME
    },
    MaxUdpPayloadSize: VarInt .into_inner() in 1200..=65527 => {
        value = 0x03,
        default = VarInt::from_u32(65527)
    },
    InitialMaxData: VarInt => {
        value = 0x04,
        default = VarInt::from_u32(0),
        flags = NOT_REDUCE
    },
    InitialMaxStreamDataBidiLocal: VarInt => {
        value = 0x05,
        default = VarInt::from_u32(0),
        flags = NOT_REDUCE
    },
    InitialMaxStreamDataBidiRemote: VarInt => {
        value = 0x06,
        default = VarInt::from_u32(0),
        flags = NOT_REDUCE
    },
    InitialMaxStreamDataUni: VarInt => {
        value = 0x07,
        default = VarInt::from_u32(0),
        flags = NOT_REDUCE
    },
    InitialMaxStreamsBidi: VarInt => {
        value = 0x08,
        default = VarInt::from_u32(0),
        flags = NOT_REDUCE
    },
    InitialMaxStreamsUni: VarInt => {
        value =  0x09,
        default = VarInt::from_u32(0),
        flags = NOT_REDUCE
    },
    AckDelayExponent: VarInt .into_inner() in 0..=20 => {
        value = 0x0a,
        default = VarInt::from_u32(3),
        flags = NOT_RESUME
    },
    MaxAckDelay: Duration .as_millis() in 0..=(1 << 14) => {
        value = 0x0b,
        default = Duration::from_millis(25),
        flags = NOT_RESUME
    },
    DisableActiveMigration: bool => {
        value = 0x0c,
        default = false
    },
    PreferredAddress: PreferredAddress => {
        value = 0x0d,
        flags = NOT_CLIENT | NOT_RESUME
    },
    ActiveConnectionIdLimit: VarInt .into_inner() in 2.. => {
        value = 0x0e,
        default = VarInt::from_u32(2),
        flags = NOT_REDUCE
    },
    InitialSourceConnectionId: ConnectionId => {
        value = 0x0f,
        flags = NOT_RESUME | CLIENT_REQUIRED | SERVER_REQUIRED
    },
    RetrySourceConnectionId: ConnectionId => {
        value = 0x10,
        flags = NOT_CLIENT | NOT_RESUME
    },
    MaxDatagramFrameSize: VarInt .into_inner() in 8..=65535 => {
        value = 0x20,
        default = VarInt::from_u32(0),
        flags = NOT_REDUCE
    },
    GreaseQuicBit: bool => {
        value = 0x2a_b2,
        default = false
    }
}

}

impl std::fmt::LowerHex for ParameterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", VarInt::from(*self).into_inner())
    }
}

/// Parse the parameter id from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub(super) fn be_parameter_id(input: &[u8]) -> nom::IResult<&[u8], ParameterId> {
    be_varint(input).map(|(remain, id)| (remain, id.into()))
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

/// The server's preferred address, which is used to effect
/// a change in server address at the end of the handshake.
///
/// See [section-18.2-4.31](https://datatracker.ietf.org/doc/html/rfc9000#section-18.2-4.32)
/// and [figure-22](https://datatracker.ietf.org/doc/html/rfc9000#figure-22)
/// for more details.
#[derive(CopyGetters, Setters, MutGetters, Debug, PartialEq, Clone, Copy)]
pub struct PreferredAddress {
    #[getset(get_copy = "pub", set = "pub")]
    address_v4: SocketAddrV4,
    #[getset(get_copy = "pub", set = "pub")]
    address_v6: SocketAddrV6,
    #[getset(get_copy = "pub", set = "pub")]
    connection_id: ConnectionId,
    #[getset(get_copy = "pub", set = "pub")]
    stateless_reset_token: ResetToken,
}

impl PreferredAddress {
    /// Create a new preferred address.
    pub fn new(
        address_v4: SocketAddrV4,
        address_v6: SocketAddrV6,
        connection_id: ConnectionId,
        stateless_reset_token: ResetToken,
    ) -> Self {
        Self {
            address_v4,
            address_v6,
            connection_id,
            stateless_reset_token,
        }
    }

    /// Returns the encoding size of the preferred address.
    pub fn encoding_size(&self) -> usize {
        6 + 18 + self.connection_id.encoding_size() + self.stateless_reset_token.encoding_size()
    }
}

/// Parse the preferred address from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_preferred_address(input: &[u8]) -> nom::IResult<&[u8], PreferredAddress> {
    use nom::{bytes::streaming::take, combinator::map};

    let (input, address_v4) = map(take(6usize), |buf: &[u8]| {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&buf[..4]);
        let port = u16::from_be_bytes([buf[4], buf[5]]);
        SocketAddrV4::new(addr.into(), port)
    })
    .parse(input)?;

    let (input, address_v6) = map(take(18usize), |buf: &[u8]| {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&buf[..16]);
        let port = u16::from_be_bytes([buf[16], buf[17]]);
        SocketAddrV6::new(addr.into(), port, 0, 0)
    })
    .parse(input)?;

    let (input, connection_id) = be_connection_id(input)?;
    let (input, stateless_reset_token) = be_reset_token(input)?;

    Ok((
        input,
        PreferredAddress {
            address_v4,
            address_v6,
            connection_id,
            stateless_reset_token,
        },
    ))
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly
/// to write the preferred address.
pub trait WirtePreferredAddress: bytes::BufMut {
    /// Write the preferred address to the buffer.
    fn put_preferred_address(&mut self, addr: &PreferredAddress);
}

impl<T: bytes::BufMut> WirtePreferredAddress for T {
    fn put_preferred_address(&mut self, addr: &PreferredAddress) {
        self.put_slice(&addr.address_v4.ip().octets());
        self.put_u16(addr.address_v4.port());

        self.put_slice(&addr.address_v6.ip().octets());
        self.put_u16(addr.address_v6.port());

        self.put_connection_id(&addr.connection_id);
        self.put_reset_token(&addr.stateless_reset_token);
    }
}

#[derive(Debug, Clone, From, TryInto, PartialEq)]
pub enum ParameterValue {
    // for custom
    Bytes(Bytes),
    ConnectionId(ConnectionId),
    Duration(Duration),
    Flag(bool),
    PreferredAddress(PreferredAddress),
    ResetToken(ResetToken),
    VarInt(VarInt),
}

impl From<u32> for ParameterValue {
    #[inline]
    fn from(value: u32) -> Self {
        ParameterValue::VarInt(VarInt::from_u32(value))
    }
}

impl TryFrom<ParameterValue> for u64 {
    type Error = <VarInt as TryFrom<ParameterValue>>::Error;

    #[inline]
    fn try_from(value: ParameterValue) -> Result<Self, Self::Error> {
        VarInt::try_from(value).map(|value| value.into_inner())
    }
}

impl TryFrom<ParameterValue> for String {
    type Error = <Bytes as TryFrom<ParameterValue>>::Error;

    #[inline]
    fn try_from(value: ParameterValue) -> Result<Self, Self::Error> {
        Bytes::try_from(value).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }
}

pub fn be_parameter(input: &[u8]) -> nom::IResult<&[u8], (ParameterId, ParameterValue)> {
    use nom::{bytes::streaming::take, combinator::map};

    let (remain, id) = be_parameter_id(input)?;
    let (remain, len) = be_varint(remain)?;
    let (remain, value) = match id {
        // cid
        ParameterId::OriginalDestinationConnectionId
        | ParameterId::InitialSourceConnectionId
        | ParameterId::RetrySourceConnectionId => {
            let parser = |input| be_connection_id_with_len(input, len.into_inner() as usize);
            map(parser, ParameterValue::ConnectionId).parse(remain)?
        }
        // duration
        ParameterId::MaxIdleTimeout | ParameterId::MaxAckDelay => map(be_varint, |varint| {
            let millis = varint.into_inner();
            Duration::from_millis(millis).into()
        })
        .parse(remain)?,
        // flag
        ParameterId::DisableActiveMigration | ParameterId::GreaseQuicBit => (remain, true.into()),
        ParameterId::StatelessResetToken => {
            map(be_reset_token, ParameterValue::ResetToken).parse(remain)?
        }
        // varint
        ParameterId::MaxUdpPayloadSize
        | ParameterId::InitialMaxData
        | ParameterId::InitialMaxStreamDataBidiLocal
        | ParameterId::InitialMaxStreamDataBidiRemote
        | ParameterId::InitialMaxStreamDataUni
        | ParameterId::InitialMaxStreamsBidi
        | ParameterId::InitialMaxStreamsUni
        | ParameterId::AckDelayExponent
        | ParameterId::ActiveConnectionIdLimit
        | ParameterId::MaxDatagramFrameSize => {
            map(be_varint, ParameterValue::VarInt).parse(remain)?
        }
        // prefer address
        ParameterId::PreferredAddress => {
            map(be_preferred_address, ParameterValue::PreferredAddress).parse(remain)?
        }
        // custom bytes
        ParameterId::Value(_) => map(take(len.into_inner() as usize), |bytes| {
            Bytes::copy_from_slice(bytes).into()
        })
        .parse(remain)?,
    };

    Ok((remain, (id, value)))
}

/// A trait for writing parameters to the buffer.
pub trait WriteParameter {
    fn put_bytes_parameter(&mut self, id: ParameterId, bytes: &Bytes);

    fn put_cid_parameter(&mut self, id: ParameterId, cid: &ConnectionId);

    fn put_duration_parameter(&mut self, id: ParameterId, dur: &Duration) {
        let value = VarInt::from_u128(dur.as_millis()).expect("Duration too large");
        self.put_varint_parameter(id, &value);
    }

    fn put_flag_parameter(&mut self, id: ParameterId, flag: &bool);

    fn put_preferred_address_parameter(&mut self, id: ParameterId, addr: &PreferredAddress);

    fn put_reset_token_parameter(&mut self, id: ParameterId, token: &ResetToken);

    fn put_varint_parameter(&mut self, id: ParameterId, value: &VarInt);

    fn put_parameter(&mut self, id: ParameterId, value: &ParameterValue) {
        match value {
            ParameterValue::Bytes(bytes) => self.put_bytes_parameter(id, bytes),
            ParameterValue::ConnectionId(cid) => self.put_cid_parameter(id, cid),
            ParameterValue::Duration(dur) => self.put_duration_parameter(id, dur),
            ParameterValue::Flag(flag) => self.put_flag_parameter(id, flag),
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

    fn put_flag_parameter(&mut self, id: ParameterId, flag: &bool) {
        if *flag {
            self.put_parameter_id(id);
            self.put_varint(&VarInt::from_u32(0));
        }
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

#[derive(Default, Debug, Clone, PartialEq)]
pub struct GeneralParameters(HashMap<ParameterId, ParameterValue>);

impl GeneralParameters {
    #[inline]
    pub fn get(&self, id: ParameterId) -> Option<ParameterValue> {
        self.0.get(&id).cloned().or_else(|| id.default_value())
    }

    #[inline]
    pub fn get_as<V>(&self, id: ParameterId) -> Option<V>
    where
        V: TryFrom<ParameterValue>,
        <V as TryFrom<ParameterValue>>::Error: Debug,
    {
        self.get(id).map(|v| v.try_into().expect("type mismatch"))
    }

    #[inline]
    pub fn set<V>(&mut self, id: ParameterId, value: V) -> Result<(), QuicError>
    where
        V: Into<ParameterValue>,
    {
        self.0.insert(id, id.check_value(value.into())?);
        Ok(())
    }

    #[inline]
    pub fn contains(&self, id: ParameterId) -> bool {
        self.0.contains_key(&id)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub trait WriteParameters {
    fn put_parameters(&mut self, params: &GeneralParameters);
}

impl<T: bytes::BufMut> WriteParameters for T {
    fn put_parameters(&mut self, params: &GeneralParameters) {
        for (id, value) in &params.0 {
            self.put_parameter(*id, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_id_conversion() {
        assert_eq!(VarInt::from(ParameterId::MaxIdleTimeout).into_inner(), 0x01);
        assert_eq!(
            VarInt::from(ParameterId::MaxUdpPayloadSize).into_inner(),
            0x03
        );
        assert_eq!(
            VarInt::from(ParameterId::GreaseQuicBit).into_inner(),
            0x2ab2
        );
    }

    #[test]
    fn test_parameter_id_encoding() {
        let mut buf = Vec::new();
        buf.put_parameter_id(ParameterId::MaxIdleTimeout);
        assert_eq!(buf, vec![0x01]);
    }

    #[test]
    fn test_parameter_id_parsing() {
        let input = [0x01];
        let (_, param_id) = be_parameter_id(&input).unwrap();
        assert_eq!(param_id, ParameterId::MaxIdleTimeout);
    }

    #[test]
    fn test_preferred_address() {
        let addr = PreferredAddress {
            address_v4: "127.0.0.1:8080".parse().unwrap(),
            address_v6: "[::1]:8081".parse().unwrap(),
            connection_id: ConnectionId::from_slice(&[1, 2, 3, 4]),
            stateless_reset_token: ResetToken::new(&[0; 16]),
        };

        let mut buf = Vec::new();
        buf.put_preferred_address(&addr);

        let (_, decoded) = be_preferred_address(&buf).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_preferred_address_encoding() {
        let prefered_addr = PreferredAddress {
            address_v4: "127.0.0.1:8080".parse().unwrap(),
            address_v6: "[::1]:8081".parse().unwrap(),
            connection_id: ConnectionId::from_slice(&[1, 2, 3, 4]),
            stateless_reset_token: ResetToken::new(&[0; 16]),
        };

        let mut buf = Vec::new();
        buf.put_preferred_address(&prefered_addr);
        assert_eq!(buf.len(), prefered_addr.encoding_size());
        assert_eq!(
            buf,
            vec![
                127, 0, 0, 1, 31, 144, // v4 address
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 31, 145, // v6 address
                4, 1, 2, 3, 4, // connection id
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 // stateless reset token
            ]
        );
    }

    #[test]
    fn test_preferred_address_parsing() {
        let input = vec![
            127, 0, 0, 1, 31, 144, // v4 address
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 31, 145, // v6 address
            4, 1, 2, 3, 4, // connection id
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // stateless reset token
        ];
        let (_, prefered_address) = be_preferred_address(&input).unwrap();
        assert_eq!(
            prefered_address,
            PreferredAddress {
                address_v4: "127.0.0.1:8080".parse().unwrap(),
                address_v6: "[::1]:8081".parse().unwrap(),
                connection_id: ConnectionId::from_slice(&[1, 2, 3, 4]),
                stateless_reset_token: ResetToken::new(&[0; 16]),
            }
        );
    }
}
