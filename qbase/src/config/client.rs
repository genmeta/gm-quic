use derive_builder::*;
use getset::*;

use super::*;
use crate::generate_validate;

#[derive(Builder, Getters, CopyGetters, Setters, MutGetters, Debug, Clone, PartialEq)]
#[builder(default, setter(strip_option, into,), build_fn(skip))]
pub struct ClientParameters {
    #[getset(get_copy = "pub", set = "pub")]
    max_idle_timeout: Duration,
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
    active_connection_id_limit: VarInt,

    #[getset(get = "pub", set = "pub")]
    initial_source_connection_id: Option<ConnectionId>,
    #[getset(get = "pub", set = "pub")]
    version_information: Option<Vec<u8>>,
    #[getset(get_copy = "pub", set = "pub")]
    max_datagram_frame_size: VarInt,
    // TOOD: 对此传输参数的支持
    #[getset(get_copy = "pub", set = "pub")]
    grease_quic_bit: bool,
}

impl Default for ClientParameters {
    fn default() -> Self {
        let params = Parameters::default();
        Self {
            max_idle_timeout: params.max_idle_timeout,
            max_udp_payload_size: params.max_udp_payload_size,
            initial_max_data: params.initial_max_data,
            initial_max_stream_data_bidi_local: params.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: params.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: params.initial_max_stream_data_uni,
            initial_max_streams_bidi: params.initial_max_streams_bidi,
            initial_max_streams_uni: params.initial_max_streams_uni,
            ack_delay_exponent: params.ack_delay_exponent,
            max_ack_delay: params.max_ack_delay,
            disable_active_migration: params.disable_active_migration,
            active_connection_id_limit: params.active_connection_id_limit,
            initial_source_connection_id: params.initial_source_connection_id,
            version_information: params.version_information,
            max_datagram_frame_size: params.max_datagram_frame_size,
            grease_quic_bit: params.grease_quic_bit,
        }
    }
}

generate_validate!(ClientParameters);

impl ClientParameters {
    pub fn builder() -> ClientParametersBuilder {
        ClientParametersBuilder::default()
    }
}

impl ClientParametersBuilder {
    pub fn build(&mut self) -> Result<ClientParameters, &'static str> {
        let default = ClientParameters::default();
        let builder = self.clone();
        let params = ClientParameters {
            max_idle_timeout: builder.max_idle_timeout.unwrap_or(default.max_idle_timeout),
            max_udp_payload_size: builder
                .max_udp_payload_size
                .unwrap_or(default.max_udp_payload_size),
            initial_max_data: builder.initial_max_data.unwrap_or(default.initial_max_data),
            initial_max_stream_data_bidi_local: builder
                .initial_max_stream_data_bidi_local
                .unwrap_or(default.initial_max_stream_data_bidi_local),
            initial_max_stream_data_bidi_remote: builder
                .initial_max_stream_data_bidi_remote
                .unwrap_or(default.initial_max_stream_data_bidi_remote),
            initial_max_stream_data_uni: builder
                .initial_max_stream_data_uni
                .unwrap_or(default.initial_max_stream_data_uni),
            initial_max_streams_bidi: builder
                .initial_max_streams_bidi
                .unwrap_or(default.initial_max_streams_bidi),
            initial_max_streams_uni: builder
                .initial_max_streams_uni
                .unwrap_or(default.initial_max_streams_uni),
            ack_delay_exponent: builder
                .ack_delay_exponent
                .unwrap_or(default.ack_delay_exponent),
            max_ack_delay: builder.max_ack_delay.unwrap_or(default.max_ack_delay),
            disable_active_migration: builder
                .disable_active_migration
                .unwrap_or(default.disable_active_migration),
            active_connection_id_limit: builder
                .active_connection_id_limit
                .unwrap_or(default.active_connection_id_limit),
            initial_source_connection_id: builder
                .initial_source_connection_id
                .unwrap_or(default.initial_source_connection_id),
            version_information: builder
                .version_information
                .unwrap_or(default.version_information),
            max_datagram_frame_size: builder
                .max_datagram_frame_size
                .unwrap_or(default.max_datagram_frame_size),
            grease_quic_bit: builder.grease_quic_bit.unwrap_or(default.grease_quic_bit),
        };
        params.validate()?;
        Ok(params)
    }
}

impl From<ClientParameters> for Parameters {
    fn from(value: ClientParameters) -> Self {
        Parameters {
            max_idle_timeout: value.max_idle_timeout,
            max_udp_payload_size: value.max_udp_payload_size,
            initial_max_data: value.initial_max_data,
            initial_max_stream_data_bidi_local: value.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: value.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: value.initial_max_stream_data_uni,
            initial_max_streams_bidi: value.initial_max_streams_bidi,
            initial_max_streams_uni: value.initial_max_streams_uni,
            ack_delay_exponent: value.ack_delay_exponent,
            max_ack_delay: value.max_ack_delay,
            disable_active_migration: value.disable_active_migration,
            active_connection_id_limit: value.active_connection_id_limit,
            initial_source_connection_id: value.initial_source_connection_id,
            version_information: value.version_information,
            max_datagram_frame_size: value.max_datagram_frame_size,
            grease_quic_bit: value.grease_quic_bit,
            ..Default::default()
        }
    }
}
