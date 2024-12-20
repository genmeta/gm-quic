use std::net::{SocketAddrV4, SocketAddrV6};

use getset::{Getters, MutGetters, Setters};

use crate::{
    cid::{be_connection_id, ConnectionId, WriteConnectionId},
    token::{be_reset_token, ResetToken, WriteResetToken},
    varint::{be_varint, VarInt, WriteVarInt},
};

/// The parameter id in the transport parameters.
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub enum ParameterId {
    OriginalDestinationConnectionId,
    MaxIdleTimeout,
    StatelssResetToken,
    MaxUdpPayloadSize,
    InitialMaxData,
    InitialMaxStreamDataBidiLocal,
    InitialMaxStreamDataBidiRemote,
    InitialMaxStreamDataUni,
    InitialMaxStreamsBidi,
    InitialMaxStreamsUni,
    AckDelayExponent,
    MaxAckDelay,
    DisableActiveMigration,
    PreferredAddress,
    ActiveConnectionIdLimit,
    InitialSourceConnectionId,
    RetrySourceConnectionId,
    MaxDatagramFrameSize,
    GreaseQuicBit,
}

impl From<ParameterId> for VarInt {
    fn from(id: ParameterId) -> Self {
        VarInt::from_u32(match id {
            ParameterId::OriginalDestinationConnectionId => 0x00,
            ParameterId::MaxIdleTimeout => 0x01,
            ParameterId::StatelssResetToken => 0x02,
            ParameterId::MaxUdpPayloadSize => 0x03,
            ParameterId::InitialMaxData => 0x04,
            ParameterId::InitialMaxStreamDataBidiLocal => 0x05,
            ParameterId::InitialMaxStreamDataBidiRemote => 0x06,
            ParameterId::InitialMaxStreamDataUni => 0x07,
            ParameterId::InitialMaxStreamsBidi => 0x08,
            ParameterId::InitialMaxStreamsUni => 0x09,
            ParameterId::AckDelayExponent => 0x0a,
            ParameterId::MaxAckDelay => 0x0b,
            ParameterId::DisableActiveMigration => 0x0c,
            ParameterId::PreferredAddress => 0x0d,
            ParameterId::ActiveConnectionIdLimit => 0x0e,
            ParameterId::InitialSourceConnectionId => 0x0f,
            ParameterId::RetrySourceConnectionId => 0x10,
            ParameterId::MaxDatagramFrameSize => 0x20,
            ParameterId::GreaseQuicBit => 0x2a_b2,
        })
    }
}

pub(super) fn be_parameter_id(input: &[u8]) -> nom::IResult<&[u8], ParameterId> {
    let (remain, id) = be_varint(input)?;
    let id = match id.into_inner() {
        0x00 => ParameterId::OriginalDestinationConnectionId,
        0x01 => ParameterId::MaxIdleTimeout,
        0x02 => ParameterId::StatelssResetToken,
        0x03 => ParameterId::MaxUdpPayloadSize,
        0x04 => ParameterId::InitialMaxData,
        0x05 => ParameterId::InitialMaxStreamDataBidiLocal,
        0x06 => ParameterId::InitialMaxStreamDataBidiRemote,
        0x07 => ParameterId::InitialMaxStreamDataUni,
        0x08 => ParameterId::InitialMaxStreamsBidi,
        0x09 => ParameterId::InitialMaxStreamsUni,
        0x0a => ParameterId::AckDelayExponent,
        0x0b => ParameterId::MaxAckDelay,
        0x0c => ParameterId::DisableActiveMigration,
        0x0d => ParameterId::PreferredAddress,
        0x0e => ParameterId::ActiveConnectionIdLimit,
        0x0f => ParameterId::InitialSourceConnectionId,
        0x10 => ParameterId::RetrySourceConnectionId,
        0x20 => ParameterId::MaxDatagramFrameSize,
        0x2a_b2 => ParameterId::GreaseQuicBit,
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Alt,
            )))
        }
    };
    Ok((remain, id))
}

pub trait WriteParameterId: bytes::BufMut {
    fn put_parameter_id(&mut self, param_id: ParameterId);
}

impl<T: bytes::BufMut> WriteParameterId for T {
    fn put_parameter_id(&mut self, param_id: ParameterId) {
        self.put_varint(&VarInt::from(param_id));
    }
}

#[derive(Getters, Setters, MutGetters, Debug, PartialEq, Clone, Copy)]
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
    pub fn encoding_size(&self) -> usize {
        6 + 18 + self.connection_id.encoding_size() + self.stateless_reset_token.encoding_size()
    }
}

pub fn be_preferred_address(input: &[u8]) -> nom::IResult<&[u8], PreferredAddress> {
    use nom::{bytes::streaming::take, combinator::map};

    let (input, address_v4) = map(take(6usize), |buf: &[u8]| {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&buf[..4]);
        let port = u16::from_be_bytes([buf[4], buf[5]]);
        SocketAddrV4::new(addr.into(), port)
    })(input)?;

    let (input, address_v6) = map(take(18usize), |buf: &[u8]| {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&buf[..16]);
        let port = u16::from_be_bytes([buf[16], buf[17]]);
        SocketAddrV6::new(addr.into(), port, 0, 0)
    })(input)?;

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

pub trait WirtePreferredAddress: bytes::BufMut {
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
