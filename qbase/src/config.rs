mod client;
mod server;
use std::{
    net::{SocketAddrV4, SocketAddrV6},
    time::Duration,
};

pub use client::*;
/// Ref. `<https://www.iana.org/assignments/quic/quic.xhtml>`
// QUIC的config配置
use derive_builder::*;
use getset::{Getters, MutGetters, Setters, *};
pub use server::*;

use super::varint::VarInt;
use crate::{cid::ConnectionId, generate_validate, token::ResetToken};

#[derive(Builder, Getters, CopyGetters, Setters, MutGetters, Debug, Clone, Copy, PartialEq)]
#[builder(
    default,
    setter(strip_option, into,),
    build_fn(skip),
    name = "CommonBuilder"
)]
pub struct Parameters {
    #[getset(get = "pub", set = "pub")]
    original_destination_connection_id: Option<ConnectionId>,
    #[getset(get_copy = "pub", set = "pub")]
    max_idle_timeout: Duration,

    #[getset(get = "pub", set = "pub")]
    statelss_reset_token: Option<ResetToken>,
    #[getset(get_copy = "pub", set = "pub")]
    max_udp_payload_size: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    initial_max_data: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    initial_max_stream_data_bidi_local: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    initial_max_stream_data_bidi_remote: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    initial_max_stream_data_uni: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    initial_max_streams_bidi: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    initial_max_streams_uni: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    ack_delay_exponent: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    max_ack_delay: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    disable_active_migration: bool,
    #[getset(get_copy = "pub", set = "pub")]
    preferred_address: Option<PreferredAddress>,
    #[getset(get_copy = "pub", set = "pub")]
    active_connection_id_limit: VarInt,

    #[getset(get_copy = "pub", set = "pub")]
    initial_source_connection_id: Option<ConnectionId>,
    #[getset(get_copy = "pub", set = "pub")]
    retry_source_connection_id: Option<ConnectionId>,
    #[getset(get_copy = "pub", set = "pub")]
    max_datagram_frame_size: VarInt,
    // TOOD: 对此传输参数的支持
    #[getset(get_copy = "pub", set = "pub")]
    grease_quic_bit: bool,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            max_idle_timeout: Duration::from_secs(10_000),
            statelss_reset_token: None,
            max_udp_payload_size: VarInt::from_u32(1472), // 65535 - 8
            initial_max_data: VarInt::from_u32(65536),
            initial_max_stream_data_bidi_local: VarInt::from_u32(1_250_000),
            initial_max_stream_data_bidi_remote: VarInt::from_u32(1_250_000),
            initial_max_stream_data_uni: VarInt::from_u32(1_250_000),
            initial_max_streams_bidi: VarInt::from_u32(100),
            initial_max_streams_uni: VarInt::from_u32(10),
            ack_delay_exponent: VarInt::from_u32(3),
            max_ack_delay: VarInt::from_u32(1000),
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: VarInt::from_u32(2),
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            max_datagram_frame_size: VarInt::from_u32(65535),
            grease_quic_bit: false,
        }
    }
}

#[macro_export(local_inner_macros)]
macro_rules! generate_validate {
    ($t:ty) => {
        impl $t {
            pub fn validate(&self) -> Result<(), &'static str> {
                if !(1200..65527).contains(&self.max_udp_payload_size.into_inner()) {
                    return Err("max_udp_payload_size must be at least 1200 bytes");
                }
                if self.ack_delay_exponent > 20 {
                    return Err("ack_delay_exponent must be at most 20");
                }
                if self.max_ack_delay > 1 << 14 {
                    return Err("max_ack_delay must be at most 2^14");
                }
                if self.active_connection_id_limit < 2 {
                    return Err("active_connection_id_limit must be at least 2");
                }
                Ok(())
            }
        }
    };
}

generate_validate!(Parameters);

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

pub mod ext {
    use std::time::Duration;

    use bytes::BufMut;
    use nom::{bytes::complete::take, combinator::map};

    use super::{Parameters, PreferredAddress};
    use crate::{
        cid::{be_connection_id, ConnectionId, WriteConnectionId, MAX_CID_SIZE},
        token::{be_reset_token, ResetToken, WriteResetToken},
        varint::{be_varint, VarInt, WriteVarInt},
    };

    pub fn be_parameters(input: &[u8]) -> nom::IResult<&[u8], Parameters> {
        let be_connection_id = |input, len: VarInt| {
            let len = len.into_inner() as usize;
            if len > MAX_CID_SIZE {
                return Err(nom::Err::Error(nom::error::make_error(
                    input,
                    nom::error::ErrorKind::TooLarge,
                )));
            }
            let (remain, bytes) = take(len)(input)?;
            Ok((remain, Some(ConnectionId::from_slice(bytes))))
        };

        let be_max_idle_timeout = |input| {
            let (remain, timeout) = be_varint(input)?;
            Ok((remain, Duration::from_secs(timeout.into_inner())))
        };

        let be_preferred_address = |input| {
            let (remain, addr) = be_preferred_address(input)?;
            Ok((remain, Some(addr)))
        };

        let be_reset_token = |input| {
            let (remain, token) = be_reset_token(input)?;
            Ok((remain, Some(token)))
        };

        let mut remain = input;
        let mut tp = Parameters::default();
        while !remain.is_empty() {
            let tag: VarInt;
            let len: VarInt;
            (remain, tag) = be_varint(remain)?;
            (remain, len) = be_varint(remain)?;
            match tag.into_inner() {
                0x00 => {
                    (remain, tp.original_destination_connection_id) = be_connection_id(remain, len)?
                }
                0x01 => (remain, tp.max_idle_timeout) = be_max_idle_timeout(remain)?,
                0x02 => (remain, tp.statelss_reset_token) = be_reset_token(remain)?,
                0x03 => (remain, tp.max_udp_payload_size) = be_varint(remain)?,
                0x04 => (remain, tp.initial_max_data) = be_varint(remain)?,
                0x05 => (remain, tp.initial_max_stream_data_bidi_local) = be_varint(remain)?,
                0x06 => (remain, tp.initial_max_stream_data_bidi_remote) = be_varint(remain)?,
                0x07 => (remain, tp.initial_max_stream_data_uni) = be_varint(remain)?,
                0x08 => (remain, tp.initial_max_streams_bidi) = be_varint(remain)?,
                0x09 => (remain, tp.initial_max_streams_uni) = be_varint(remain)?,
                0x0a => (remain, tp.ack_delay_exponent) = be_varint(remain)?,
                0x0b => (remain, tp.max_ack_delay) = be_varint(remain)?,
                0x0c => tp.disable_active_migration = true,
                0x0d => (remain, tp.preferred_address) = be_preferred_address(remain)?,
                0x0e => (remain, tp.active_connection_id_limit) = be_varint(remain)?,
                0x0f => (remain, tp.initial_source_connection_id) = be_connection_id(remain, len)?,
                0x10 => (remain, tp.retry_source_connection_id) = be_connection_id(remain, len)?,
                0x20 => (remain, tp.max_datagram_frame_size) = be_varint(remain)?,
                // 0x2ab2 => tp.grease_quic_bit = true,
                _ => {
                    // Ref. `<https://www.rfc-editor.org/rfc/rfc9000.html#name-new-transport-parameters>
                    // An endpoint MUST ignore transport parameters that it does not support.

                    // take it, and ignore it
                    (remain, ..) = take(len)(remain)?;
                }
            }
        }

        Ok((remain, tp))
    }

    pub trait WriteParameters {
        fn put_parameters(&mut self, params: &Parameters);
        fn put_preferred_address(&mut self, addr: &super::PreferredAddress);
    }

    impl<T: BufMut> WriteParameters for T {
        fn put_parameters(&mut self, params: &Parameters) {
            let put_varint = |buf: &mut Self, tag: u8, varint: VarInt| {
                if varint.into_inner() > 0 {
                    buf.put_u8(tag);
                    buf.put_varint(&unsafe {
                        VarInt::from_u64_unchecked(varint.encoding_size() as u64)
                    });
                    buf.put_varint(&varint);
                }
            };

            let put_connection_id = |buf: &mut Self, tag: u8, cid: &Option<ConnectionId>| {
                if let Some(cid) = cid {
                    buf.put_u8(tag);
                    buf.put_connection_id(cid);
                }
            };

            let put_reset_token = |buf: &mut Self, tag: u8, token: &Option<ResetToken>| {
                if let Some(token) = token {
                    buf.put_u8(tag);
                    buf.put_varint(&unsafe {
                        VarInt::from_u64_unchecked(token.encoding_size() as u64)
                    });
                    buf.put_reset_token(token);
                }
            };

            let put_preferred_address =
                |buf: &mut Self, tag: u8, addr: &Option<PreferredAddress>| {
                    if let Some(addr) = addr {
                        buf.put_u8(tag);
                        buf.put_varint(&unsafe {
                            VarInt::from_u64_unchecked(addr.encoding_size() as u64)
                        });
                        buf.put_preferred_address(addr);
                    }
                };

            put_connection_id(self, 0x00, &params.original_destination_connection_id);
            put_varint(
                self,
                0x01,
                VarInt::from_u64(params.max_idle_timeout.as_secs())
                    .expect("max_idle timeout can not exceed 2^62 seconds"),
            );
            put_reset_token(self, 0x02, &params.statelss_reset_token);
            put_varint(self, 0x03, params.max_udp_payload_size);
            put_varint(self, 0x04, params.initial_max_data);
            put_varint(self, 0x05, params.initial_max_stream_data_bidi_local);
            put_varint(self, 0x06, params.initial_max_stream_data_bidi_remote);
            put_varint(self, 0x07, params.initial_max_stream_data_uni);
            put_varint(self, 0x08, params.initial_max_streams_bidi);
            put_varint(self, 0x09, params.initial_max_streams_uni);
            put_varint(self, 0x0a, params.ack_delay_exponent);
            put_varint(self, 0x0b, params.max_ack_delay);
            if params.disable_active_migration {
                self.put_u8(0x0c);
                self.put_u8(0);
            }
            put_preferred_address(self, 0x0d, &params.preferred_address);
            put_varint(self, 0x0e, params.active_connection_id_limit);
            put_connection_id(self, 0x0f, &params.initial_source_connection_id);
            put_connection_id(self, 0x10, &params.retry_source_connection_id);
            put_varint(self, 0x20, params.max_datagram_frame_size);
            // if params.grease_quic_bit {
            //     self.put_varint(&VarInt::from_u32(0x2ab2));
            //     self.put_u8(0);
            // }
        }

        fn put_preferred_address(&mut self, addr: &super::PreferredAddress) {
            self.put_slice(&addr.address_v4.ip().octets());
            self.put_u16(addr.address_v4.port());

            self.put_slice(&addr.address_v6.ip().octets());
            self.put_u16(addr.address_v6.port());

            self.put_connection_id(&addr.connection_id);
            self.put_reset_token(&addr.stateless_reset_token);
        }
    }

    pub fn be_preferred_address(input: &[u8]) -> nom::IResult<&[u8], super::PreferredAddress> {
        use nom::bytes::streaming::take;

        let (input, address_v4) = map(take(6usize), |buf: &[u8]| {
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&buf[..4]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            std::net::SocketAddrV4::new(addr.into(), port)
        })(input)?;

        let (input, address_v6) = map(take(18usize), |buf: &[u8]| {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&buf[..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            std::net::SocketAddrV6::new(addr.into(), port, 0, 0)
        })(input)?;

        let (input, connection_id) = be_connection_id(input)?;
        let (input, stateless_reset_token) = be_reset_token(input)?;

        Ok((
            input,
            super::PreferredAddress {
                address_v4,
                address_v6,
                connection_id,
                stateless_reset_token,
            },
        ))
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use super::{ext::WriteParameters, *};
    use crate::{cid::be_connection_id, token::RESET_TOKEN_SIZE};

    #[test]
    fn coding() {
        let init_cid = be_connection_id(&[0x04, 0x01, 0x02, 0x03, 0x04]).unwrap().1;
        let orgin_cid = be_connection_id(&[0x04, 0x05, 0x06, 0x07, 0x08]).unwrap().1;
        let params = ServerParameters::builder()
            .original_destination_connection_id(orgin_cid)
            .max_idle_timeout(Duration::from_secs(10_000))
            .statelss_reset_token(ResetToken::new(&[0x01; RESET_TOKEN_SIZE]))
            .max_udp_payload_size(VarInt::from_u32(1472))
            .initial_max_data(VarInt::from_u32(65536))
            .initial_max_stream_data_bidi_local(VarInt::from_u32(1_250_000))
            .initial_max_stream_data_bidi_remote(VarInt::from_u32(1_250_000))
            .initial_max_stream_data_uni(VarInt::from_u32(1_250_000))
            .initial_max_streams_bidi(VarInt::from_u32(100))
            .initial_max_streams_uni(VarInt::from_u32(10))
            .ack_delay_exponent(VarInt::from_u32(0x12))
            .max_ack_delay(VarInt::from_u32(0x98))
            .disable_active_migration(true)
            .preferred_address(PreferredAddress {
                address_v4: SocketAddrV4::new(Ipv4Addr::new(0x01, 0x02, 0x03, 0x04), 0x1234),
                address_v6: SocketAddrV6::new(
                    std::net::Ipv6Addr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08),
                    0x1234,
                    0,
                    0,
                ),
                connection_id: init_cid,
                stateless_reset_token: ResetToken::new(&[0x02; RESET_TOKEN_SIZE]),
            })
            .active_connection_id_limit(VarInt::from_u32(0x1234))
            .initial_source_connection_id(init_cid)
            .retry_source_connection_id(init_cid)
            .max_datagram_frame_size(VarInt::from_u32(65535))
            .grease_quic_bit(false)
            .build()
            .unwrap()
            .into();

        let mut buf = bytes::BytesMut::new();
        buf.put_parameters(&params);
        let params2 = ext::be_parameters(&buf).unwrap().1;
        assert_eq!(params, params2);
    }

    #[test]
    fn invalid_params() {
        let build_result = ClientParameters::builder()
            .max_udp_payload_size(VarInt::from_u32(1199))
            .build();
        assert!(build_result.is_err());

        let build_result = ClientParameters::builder()
            .ack_delay_exponent(VarInt::from_u32(21))
            .build();
        assert!(build_result.is_err());

        let build_result = ClientParameters::builder()
            .active_connection_id_limit(VarInt::from_u32(1))
            .build();
        assert!(build_result.is_err());
    }

    #[test]
    fn default_params_test() {
        let params = Parameters::default();
        params.validate().unwrap();
    }
}
