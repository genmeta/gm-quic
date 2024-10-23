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

pub mod codec;

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use super::{codec::WriteParameters, *};
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
        let params2 = codec::be_parameters(&buf).unwrap().1;
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
