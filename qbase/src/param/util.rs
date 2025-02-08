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

/// Parse the parameter id from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
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
    use nom::{bytes::streaming::take, combinator::map, Parser};

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
