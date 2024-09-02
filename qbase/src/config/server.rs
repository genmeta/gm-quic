use getset::*;

use super::*;

#[derive(Builder, Getters, CopyGetters, Setters, MutGetters, Debug, Clone, PartialEq)]
#[builder(default, setter(strip_option, into,), build_fn(skip))]
pub struct ServerParameters {
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
    #[getset(get = "pub", set = "pub")]
    version_information: Option<Vec<u8>>,
    #[getset(get_copy = "pub", set = "pub")]
    max_datagram_frame_size: VarInt,
    // TOOD: 对此传输参数的支持
    #[getset(get_copy = "pub", set = "pub")]
    grease_quic_bit: bool,
}

impl ServerParameters {
    pub fn builder() -> ServerParametersBuilder {
        ServerParametersBuilder::default()
    }
}

generate_validate!(ServerParameters);

impl ServerParametersBuilder {
    pub fn build(&mut self) -> Result<ServerParameters, &'static str> {
        let default = Parameters::default();
        let this = self.clone();
        let params = ServerParameters {
            original_destination_connection_id: this
                .original_destination_connection_id
                .unwrap_or(default.original_destination_connection_id),
            max_idle_timeout: this.max_idle_timeout.unwrap_or(default.max_idle_timeout),
            statelss_reset_token: this
                .statelss_reset_token
                .unwrap_or(default.statelss_reset_token),
            max_udp_payload_size: this
                .max_udp_payload_size
                .unwrap_or(default.max_udp_payload_size),
            initial_max_data: this.initial_max_data.unwrap_or(default.initial_max_data),
            initial_max_stream_data_bidi_local: this
                .initial_max_stream_data_bidi_local
                .unwrap_or(default.initial_max_stream_data_bidi_local),
            initial_max_stream_data_bidi_remote: this
                .initial_max_stream_data_bidi_remote
                .unwrap_or(default.initial_max_stream_data_bidi_remote),
            initial_max_stream_data_uni: this
                .initial_max_stream_data_uni
                .unwrap_or(default.initial_max_stream_data_uni),
            initial_max_streams_bidi: this
                .initial_max_streams_bidi
                .unwrap_or(default.initial_max_streams_bidi),
            initial_max_streams_uni: this
                .initial_max_streams_uni
                .unwrap_or(default.initial_max_streams_uni),
            ack_delay_exponent: this
                .ack_delay_exponent
                .unwrap_or(default.ack_delay_exponent),
            max_ack_delay: this.max_ack_delay.unwrap_or(default.max_ack_delay),
            disable_active_migration: this
                .disable_active_migration
                .unwrap_or(default.disable_active_migration),
            preferred_address: this.preferred_address.unwrap_or(default.preferred_address),
            active_connection_id_limit: this
                .active_connection_id_limit
                .unwrap_or(default.active_connection_id_limit),
            initial_source_connection_id: this
                .initial_source_connection_id
                .unwrap_or(default.initial_source_connection_id),
            retry_source_connection_id: this
                .retry_source_connection_id
                .unwrap_or(default.retry_source_connection_id),
            version_information: this
                .version_information
                .unwrap_or(default.version_information),
            max_datagram_frame_size: this
                .max_datagram_frame_size
                .unwrap_or(default.max_datagram_frame_size),
            grease_quic_bit: this.grease_quic_bit.unwrap_or(default.grease_quic_bit),
        };
        params.validate()?;
        Ok(params)
    }
}

impl From<ServerParameters> for Parameters {
    fn from(value: ServerParameters) -> Self {
        Parameters {
            original_destination_connection_id: value.original_destination_connection_id,
            max_idle_timeout: value.max_idle_timeout,
            statelss_reset_token: value.statelss_reset_token,
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
            preferred_address: value.preferred_address,
            active_connection_id_limit: value.active_connection_id_limit,
            initial_source_connection_id: value.initial_source_connection_id,
            retry_source_connection_id: value.retry_source_connection_id,
            version_information: value.version_information,
            max_datagram_frame_size: value.max_datagram_frame_size,
            grease_quic_bit: value.grease_quic_bit,
        }
    }
}
