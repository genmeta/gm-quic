use std::time::Duration;

use deref_derive::{Deref, DerefMut};
use getset::{CopyGetters, Setters};
use nom::combinator::map;

use super::{
    be_parameter_id, be_preferred_address, ParameterId, PreferredAddress, WirtePreferredAddress,
    WriteParameterId,
};
use crate::{
    cid::{be_connection_id_with_len, ConnectionId, WriteConnectionId},
    sid::MAX_STREAMS_LIMIT,
    token::{be_reset_token, ResetToken, WriteResetToken},
    varint::{be_varint, VarInt, WriteVarInt},
};

#[derive(CopyGetters, Setters, Debug, Clone, Copy, PartialEq)]
pub struct CommonParameters {
    #[getset(get_copy = "pub", set = "pub")]
    pub(super) max_idle_timeout: Duration,
    #[getset(get_copy = "pub")]
    pub(super) max_udp_payload_size: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    pub(super) max_datagram_frame_size: VarInt,
    #[getset(get_copy = "pub")]
    pub(super) ack_delay_exponent: VarInt,
    #[getset(get_copy = "pub")]
    pub(super) max_ack_delay: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    pub(super) disable_active_migration: bool,
    #[getset(get_copy = "pub")]
    pub(super) active_connection_id_limit: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    pub(super) initial_max_data: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    pub(super) initial_max_stream_data_bidi_local: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    pub(super) initial_max_stream_data_bidi_remote: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    pub(super) initial_max_stream_data_uni: VarInt,
    #[getset(get_copy = "pub")]
    pub(super) initial_max_streams_bidi: VarInt,
    #[getset(get_copy = "pub")]
    pub(super) initial_max_streams_uni: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    pub(super) initial_source_connection_id: ConnectionId,
    // TOOD: 对此传输参数的支持
    #[getset(get_copy = "pub", set = "pub")]
    pub(super) grease_quic_bit: bool,
}

impl Default for CommonParameters {
    fn default() -> Self {
        Self {
            // Idle timeout is disabled when both endpoints
            // omit this transport parameter or specify a value of 0.
            max_idle_timeout: Duration::ZERO,
            // The default for this parameter is the maximum permitted UDP payload of 65527.
            max_udp_payload_size: VarInt::from_u32(65527),
            // For most uses of DATAGRAM frames, it is RECOMMENDED to send a value of 65535
            // in the max_datagram_frame_size transport parameter to indicate that this
            // endpoint will accept any DATAGRAM frame that fits inside a QUIC packet.
            max_datagram_frame_size: VarInt::from_u32(65535),
            // If this value is absent, a default value of 3 is assumed (indicating a multiplier of 8).
            ack_delay_exponent: VarInt::from_u32(3),
            // If this value is absent, a default of 25 milliseconds is assumed.
            max_ack_delay: VarInt::from_u32(25),
            disable_active_migration: false,
            // If this transport parameter is absent, a default of 2 is assumed.
            active_connection_id_limit: VarInt::from_u32(2),
            initial_max_data: VarInt::default(),
            initial_max_stream_data_bidi_local: VarInt::default(),
            initial_max_stream_data_bidi_remote: VarInt::default(),
            initial_max_stream_data_uni: VarInt::default(),
            initial_max_streams_bidi: VarInt::default(),
            initial_max_streams_uni: VarInt::default(),
            initial_source_connection_id: ConnectionId::default(),
            grease_quic_bit: false,
        }
    }
}

impl CommonParameters {
    pub fn set_max_udp_payload_size(&mut self, size: u32) -> &mut Self {
        assert!(
            size >= 1200,
            "Values below 1200 are invalid for max_udp_payload_size"
        );
        self.max_udp_payload_size = VarInt::from_u32(size);
        self
    }

    pub fn set_ack_delay_exponent(&mut self, exponent: u8) -> &mut Self {
        assert!(
            exponent <= 20,
            "Values above 20 are invalid for ack_delay_exponent"
        );
        self.ack_delay_exponent = VarInt::from_u32(exponent as u32);
        self
    }

    pub fn set_max_ack_delay(&mut self, delay: u16) -> &mut Self {
        assert!(
            delay <= 1 << 14,
            "Values of 2^14 or greater are invalid for max_ack_delay"
        );
        self.max_ack_delay = VarInt::from_u32(delay as u32);
        self
    }

    pub fn set_active_connection_id_limit(&mut self, limit: u64) -> &mut Self {
        assert!(
            limit >= 2,
            "The value of the active_connection_id_limit parameter MUST be at least 2"
        );
        self.active_connection_id_limit = VarInt::from_u64(limit)
            .expect("The value of the active_connection_id_limit cannot exceed 2^62-1");
        self
    }

    pub fn set_initial_max_streams_bidi(&mut self, streams: u64) -> &mut Self {
        assert!(
            streams <= MAX_STREAMS_LIMIT,
            "The value of the initial_max_streams_bidi transport parameter cannot exceed 2^60-1"
        );
        self.initial_max_streams_bidi = VarInt::from_u64(streams).unwrap();
        self
    }

    pub fn set_initial_max_streams_uni(&mut self, streams: u64) -> &mut Self {
        assert!(
            streams <= MAX_STREAMS_LIMIT,
            "The value of the initial_max_streams_uni transport parameter cannot exceed 2^60-1"
        );
        self.initial_max_streams_uni = VarInt::from_u64(streams).unwrap();
        self
    }
}

pub trait WriteCommonParameters: bytes::BufMut {
    fn put_varint_parameter(&mut self, id: ParameterId, varint: VarInt);

    fn put_cid_parameter(&mut self, id: ParameterId, cid: &ConnectionId);

    fn put_common_parameters(&mut self, params: &CommonParameters);
}

impl<T: bytes::BufMut> WriteCommonParameters for T {
    fn put_varint_parameter(&mut self, id: ParameterId, value: VarInt) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::from_u64(value.encoding_size() as u64).unwrap());
        self.put_varint(&value);
    }

    fn put_cid_parameter(&mut self, id: ParameterId, value: &ConnectionId) {
        self.put_parameter_id(id);
        self.put_connection_id(value);
    }

    fn put_common_parameters(&mut self, parameters: &CommonParameters) {
        self.put_varint_parameter(
            ParameterId::MaxIdleTimeout,
            VarInt::from_u64(parameters.max_idle_timeout.as_secs())
                .expect("max_idle timeout can not exceed 2^62 seconds"),
        );
        self.put_varint_parameter(
            ParameterId::MaxUdpPayloadSize,
            parameters.max_udp_payload_size,
        );
        self.put_varint_parameter(ParameterId::InitialMaxData, parameters.initial_max_data);
        self.put_varint_parameter(
            ParameterId::InitialMaxStreamDataBidiLocal,
            parameters.initial_max_stream_data_bidi_local,
        );
        self.put_varint_parameter(
            ParameterId::InitialMaxStreamDataBidiRemote,
            parameters.initial_max_stream_data_bidi_remote,
        );
        self.put_varint_parameter(
            ParameterId::InitialMaxStreamDataUni,
            parameters.initial_max_stream_data_uni,
        );
        self.put_varint_parameter(
            ParameterId::InitialMaxStreamsBidi,
            parameters.initial_max_streams_bidi,
        );
        self.put_varint_parameter(
            ParameterId::InitialMaxStreamsUni,
            parameters.initial_max_streams_uni,
        );
        self.put_varint_parameter(ParameterId::AckDelayExponent, parameters.ack_delay_exponent);
        self.put_varint_parameter(ParameterId::MaxAckDelay, parameters.max_ack_delay);
        if parameters.disable_active_migration {
            self.put_parameter_id(ParameterId::DisableActiveMigration);
            self.put_varint(&VarInt::from_u32(0));
        }
        self.put_varint_parameter(
            ParameterId::ActiveConnectionIdLimit,
            parameters.active_connection_id_limit,
        );
        self.put_cid_parameter(
            ParameterId::InitialSourceConnectionId,
            &parameters.initial_source_connection_id,
        );
        self.put_varint_parameter(
            ParameterId::MaxDatagramFrameSize,
            parameters.max_datagram_frame_size,
        );
        if parameters.grease_quic_bit {
            self.put_parameter_id(ParameterId::GreaseQuicBit);
            self.put_varint(&VarInt::from_u32(0));
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Deref, DerefMut)]
pub struct ClientParameters(CommonParameters);

pub(super) fn be_client_parameters<'b>(
    mut input: &'b [u8],
    params: &mut ClientParameters,
) -> nom::IResult<&'b [u8], ()> {
    while !input.is_empty() {
        let (remain, id) = be_parameter_id(input)?;
        let (remain, len) = be_varint(remain)?;
        match id {
            ParameterId::MaxIdleTimeout => {
                (input, params.max_idle_timeout) =
                    map(be_varint, |v| Duration::from_secs(v.into_inner()))(remain)?
            }
            ParameterId::MaxUdpPayloadSize => {
                (input, params.max_udp_payload_size) = be_varint(remain)?
            }
            ParameterId::InitialMaxData => (input, params.initial_max_data) = be_varint(remain)?,
            ParameterId::InitialMaxStreamDataBidiLocal => {
                (input, params.initial_max_stream_data_bidi_local) = be_varint(remain)?
            }
            ParameterId::InitialMaxStreamDataBidiRemote => {
                (input, params.initial_max_stream_data_bidi_remote) = be_varint(remain)?
            }
            ParameterId::InitialMaxStreamDataUni => {
                (input, params.initial_max_stream_data_uni) = be_varint(remain)?
            }
            ParameterId::InitialMaxStreamsBidi => {
                (input, params.initial_max_streams_bidi) = be_varint(remain)?
            }
            ParameterId::InitialMaxStreamsUni => {
                (input, params.initial_max_streams_uni) = be_varint(remain)?
            }
            ParameterId::AckDelayExponent => {
                (input, params.ack_delay_exponent) = be_varint(remain)?
            }
            ParameterId::MaxAckDelay => (input, params.max_ack_delay) = be_varint(remain)?,
            ParameterId::DisableActiveMigration => {
                (input, params.disable_active_migration) = (remain, true)
            }
            ParameterId::ActiveConnectionIdLimit => {
                (input, params.active_connection_id_limit) = be_varint(remain)?
            }
            ParameterId::InitialSourceConnectionId => {
                (input, params.initial_source_connection_id) =
                    be_connection_id_with_len(remain, len.into_inner() as usize)?
            }
            ParameterId::MaxDatagramFrameSize => {
                (input, params.max_datagram_frame_size) = be_varint(remain)?
            }
            ParameterId::GreaseQuicBit => (input, params.grease_quic_bit) = (remain, true),
            _ => (),
        }
    }
    Ok((input, ()))
}

pub trait WriteClientParameters: WriteCommonParameters {
    fn put_client_parameters(&mut self, params: &ClientParameters);
}

impl<T: bytes::BufMut> WriteClientParameters for T {
    fn put_client_parameters(&mut self, params: &ClientParameters) {
        self.put_common_parameters(&params.0);
    }
}

#[derive(Debug, Default, CopyGetters, Setters, Clone, Copy, Deref, DerefMut)]
pub struct ServerParameters {
    #[deref]
    common_params: CommonParameters,
    #[getset(get = "pub")]
    pub(super) original_destination_connection_id: ConnectionId,
    #[getset(get_copy = "pub")]
    pub(super) retry_source_connection_id: Option<ConnectionId>,
    #[getset(get = "pub")]
    pub(super) preferred_address: Option<PreferredAddress>,
    #[getset(get = "pub")]
    pub(super) statelss_reset_token: Option<ResetToken>,
}

impl ServerParameters {
    pub fn set_original_destination_connection_id(&mut self, cid: ConnectionId) -> &mut Self {
        self.original_destination_connection_id = cid;
        self
    }

    pub fn set_retry_source_connection_id(&mut self, cid: ConnectionId) -> &mut Self {
        self.retry_source_connection_id = Some(cid);
        self
    }

    pub fn set_preferred_address(&mut self, addr: PreferredAddress) -> &mut Self {
        self.preferred_address = Some(addr);
        self
    }

    pub fn set_statelss_reset_token(&mut self, token: ResetToken) -> &mut Self {
        self.statelss_reset_token = Some(token);
        self
    }
}

pub(super) fn be_server_parameters<'b>(
    mut input: &'b [u8],
    params: &mut ServerParameters,
) -> nom::IResult<&'b [u8], ()> {
    while !input.is_empty() {
        let (remain, id) = be_parameter_id(input)?;
        let (remain, len) = be_varint(remain)?;
        match id {
            ParameterId::OriginalDestinationConnectionId => {
                (input, params.original_destination_connection_id) =
                    be_connection_id_with_len(remain, len.into_inner() as usize)?;
            }
            ParameterId::MaxIdleTimeout => {
                (input, params.max_idle_timeout) =
                    map(be_varint, |v| Duration::from_secs(v.into_inner()))(remain)?
            }
            ParameterId::StatelssResetToken => {
                (input, params.statelss_reset_token) =
                    be_reset_token(remain).map(|(remain, token)| (remain, Some(token)))?
            }
            ParameterId::MaxUdpPayloadSize => {
                (input, params.max_udp_payload_size) = be_varint(remain)?
            }
            ParameterId::InitialMaxData => (input, params.initial_max_data) = be_varint(remain)?,
            ParameterId::InitialMaxStreamDataBidiLocal => {
                (input, params.initial_max_stream_data_bidi_local) = be_varint(remain)?
            }
            ParameterId::InitialMaxStreamDataBidiRemote => {
                (input, params.initial_max_stream_data_bidi_remote) = be_varint(remain)?
            }
            ParameterId::InitialMaxStreamDataUni => {
                (input, params.initial_max_stream_data_uni) = be_varint(remain)?
            }
            ParameterId::InitialMaxStreamsBidi => {
                (input, params.initial_max_streams_bidi) = be_varint(remain)?
            }
            ParameterId::InitialMaxStreamsUni => {
                (input, params.initial_max_streams_uni) = be_varint(remain)?
            }
            ParameterId::AckDelayExponent => {
                (input, params.ack_delay_exponent) = be_varint(remain)?
            }
            ParameterId::MaxAckDelay => (input, params.max_ack_delay) = be_varint(remain)?,
            ParameterId::DisableActiveMigration => {
                (input, params.disable_active_migration) = (remain, true)
            }
            ParameterId::PreferredAddress => {
                (input, params.preferred_address) =
                    be_preferred_address(remain).map(|(remain, addr)| (remain, Some(addr)))?
            }
            ParameterId::ActiveConnectionIdLimit => {
                (input, params.active_connection_id_limit) = be_varint(remain)?
            }
            ParameterId::InitialSourceConnectionId => {
                (input, params.initial_source_connection_id) =
                    be_connection_id_with_len(remain, len.into_inner() as usize)?
            }
            ParameterId::RetrySourceConnectionId => {
                (input, params.retry_source_connection_id) =
                    be_connection_id_with_len(remain, len.into_inner() as usize)
                        .map(|(remain, cid)| (remain, Some(cid)))?
            }
            ParameterId::MaxDatagramFrameSize => {
                (input, params.max_datagram_frame_size) = be_varint(remain)?
            }
            ParameterId::GreaseQuicBit => (input, params.grease_quic_bit) = (remain, true),
        }
    }
    Ok((input, ()))
}

pub trait WriteServerParameters: WriteCommonParameters {
    fn put_reset_token_parameter(&mut self, id: ParameterId, token: &ResetToken);
    fn put_preferred_address_parameter(&mut self, id: ParameterId, addr: &PreferredAddress);
    fn put_server_parameters(&mut self, params: &ServerParameters);
}

impl<T: bytes::BufMut> WriteServerParameters for T {
    fn put_reset_token_parameter(&mut self, id: ParameterId, value: &ResetToken) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::from_u64(value.encoding_size() as u64).unwrap());
        self.put_reset_token(value);
    }

    fn put_preferred_address_parameter(&mut self, id: ParameterId, value: &PreferredAddress) {
        self.put_parameter_id(id);
        self.put_varint(&VarInt::from_u64(value.encoding_size() as u64).unwrap());
        self.put_preferred_address(value);
    }

    fn put_server_parameters(&mut self, parameters: &ServerParameters) {
        self.put_common_parameters(&parameters.common_params);
        self.put_cid_parameter(
            ParameterId::OriginalDestinationConnectionId,
            &parameters.original_destination_connection_id,
        );
        if let Some(token) = &parameters.statelss_reset_token {
            self.put_reset_token_parameter(ParameterId::StatelssResetToken, token);
        }
        if let Some(addr) = &parameters.preferred_address {
            self.put_preferred_address_parameter(ParameterId::PreferredAddress, addr);
        }
        if let Some(cid) = &parameters.retry_source_connection_id {
            self.put_cid_parameter(ParameterId::RetrySourceConnectionId, cid);
        }
    }
}
