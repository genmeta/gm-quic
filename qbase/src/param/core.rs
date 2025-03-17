use std::time::Duration;

use deref_derive::{Deref, DerefMut};
use getset::{CopyGetters, Setters};
use nom::{Parser, combinator::map};

use super::{
    ParameterId, PreferredAddress, WirtePreferredAddress, WriteParameterId, be_parameter_id,
    be_preferred_address,
};
use crate::{
    cid::{ConnectionId, WriteConnectionId, be_connection_id_with_len},
    sid::MAX_STREAMS_LIMIT,
    token::{ResetToken, WriteResetToken, be_reset_token},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// Common parameters shared between client and server.
///
/// All transport parameters owned by the client are also owned by the server.
/// However, not all server transport parameters are available to the client,
/// including:
/// - `original_destination_connection_id`
/// - `retry_source_connection_id`
/// - `preferred_address`
/// - `stateless_reset_token`.
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
    // TOOD: 对此传输参数的支持，以及支持后修改qlog中对此的解析
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
    /// Set tht `max_udp_payload_size` transport parameter.
    ///
    /// The default for this parameter is the maximum permitted
    /// UDP payload of 65527. Values below 1200 are invalid.
    ///
    /// See [section-18.2-4.7](https://datatracker.ietf.org/doc/html/rfc9000#section-18.2-4.7)
    /// for more information.
    pub fn set_max_udp_payload_size(&mut self, size: u32) -> &mut Self {
        assert!(
            size >= 1200,
            "Values below 1200 are invalid for max_udp_payload_size"
        );
        self.max_udp_payload_size = VarInt::from_u32(size);
        self
    }

    /// Set the `max_datagram_frame_size` transport parameter.
    ///
    /// If this value is absent, a default value of 3 is assumed
    /// (indicating a multiplier of 8). Values above 20 are invalid.
    ///
    /// See [section-18.2-4.25](https://datatracker.ietf.org/doc/html/rfc9000#section-18.2-4.25)
    /// for more information.
    pub fn set_ack_delay_exponent(&mut self, exponent: u8) -> &mut Self {
        assert!(
            exponent <= 20,
            "Values above 20 are invalid for ack_delay_exponent"
        );
        self.ack_delay_exponent = VarInt::from_u32(exponent as u32);
        self
    }

    /// Set the `max_ack_delay` transport parameter.
    ///
    /// If this value is absent, a default of 25 milliseconds is assumed.
    /// Values of 214 or greater are invalid.
    ///
    /// See [section-18.2-4.27](https://datatracker.ietf.org/doc/html/rfc9000#section-18.2-4.27)
    /// for more information.
    pub fn set_max_ack_delay(&mut self, delay: u16) -> &mut Self {
        assert!(
            delay <= 1 << 14,
            "Values of 2^14 or greater are invalid for max_ack_delay"
        );
        self.max_ack_delay = VarInt::from_u32(delay as u32);
        self
    }

    /// Set the `active_connection_id_limit` transport parameter.
    ///
    /// The value of the active_connection_id_limit parameter MUST be at least 2.
    /// An endpoint that receives a value less than 2 MUST close the connection
    /// with an error of type TRANSPORT_PARAMETER_ERROR.
    /// If this transport parameter is absent, a default of 2 is assumed.
    ///
    /// See [section-18.2-6.1](https://datatracker.ietf.org/doc/html/rfc9000#section-18.2-6.1)
    /// for more information.
    pub fn set_active_connection_id_limit(&mut self, limit: u64) -> &mut Self {
        assert!(
            limit >= 2,
            "The value of the active_connection_id_limit parameter MUST be at least 2"
        );
        self.active_connection_id_limit = VarInt::from_u64(limit)
            .expect("The value of the active_connection_id_limit cannot exceed 2^62-1");
        self
    }

    /// Set the `initial_max_data` transport parameter,
    /// which can not exceed 2^60-1.
    pub fn set_initial_max_streams_bidi(&mut self, streams: u64) -> &mut Self {
        assert!(
            streams <= MAX_STREAMS_LIMIT,
            "The value of the initial_max_streams_bidi transport parameter cannot exceed 2^60-1"
        );
        self.initial_max_streams_bidi = VarInt::from_u64(streams).unwrap();
        self
    }

    /// Set the `initial_max_streams_uni` transport parameter,
    /// which can not exceed 2^60-1.
    pub fn set_initial_max_streams_uni(&mut self, streams: u64) -> &mut Self {
        assert!(
            streams <= MAX_STREAMS_LIMIT,
            "The value of the initial_max_streams_uni transport parameter cannot exceed 2^60-1"
        );
        self.initial_max_streams_uni = VarInt::from_u64(streams).unwrap();
        self
    }
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly
/// to write common parameters.
pub trait WriteCommonParameters: bytes::BufMut {
    /// Write a varint parameter with its patameter id.
    fn put_varint_parameter(&mut self, id: ParameterId, varint: VarInt);

    /// Write a connection id parameter with its patameter id.
    ///
    /// Note that the length of the connection id is encoded
    /// in the Transport Parameter Length.
    fn put_cid_parameter(&mut self, id: ParameterId, cid: &ConnectionId);

    /// Write all common parameters to the buffer.
    ///
    /// Each transport parameter is encoded as an (identifier, length, value) tuple,
    /// see [Figure 21](https://datatracker.ietf.org/doc/html/rfc9000#transport-parameter-encoding-fig)
    /// for more information.
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
            VarInt::from_u128(parameters.max_idle_timeout.as_millis())
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

/// Client transport parameters, which are similar to CommonParameters.
#[derive(Debug, Default, Clone, Copy, Deref, DerefMut)]
pub struct ClientParameters(CommonParameters);

/// Parse client transport parameters from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
///
/// As a server, it will parse the client transport parameters
/// upon receiving the Initial packet from the client.
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
                    map(be_varint, |v| Duration::from_millis(v.into_inner())).parse(remain)?
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
            _ => {
                return Err(nom::Err::Failure(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::IsNot,
                )));
            }
        }
    }
    Ok((input, ()))
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly
/// to write client parameters.
pub trait WriteClientParameters: WriteCommonParameters {
    /// Write all client parameters to the buffer.
    fn put_client_parameters(&mut self, params: &ClientParameters);
}

impl<T: bytes::BufMut> WriteClientParameters for T {
    fn put_client_parameters(&mut self, params: &ClientParameters) {
        self.put_common_parameters(&params.0);
    }
}

/// Server transport parameters, which are not only include CommonParameters,
/// but also include some additional parameters, such as
/// - `original_destination_connection_id`
/// - `retry_source_connection_id`
/// - `preferred_address`
/// - `stateless_reset_token`.
#[derive(Debug, Default, CopyGetters, Setters, Clone, Copy, Deref, DerefMut)]
pub struct ServerParameters {
    #[deref]
    common_params: CommonParameters,
    #[getset(get_copy = "pub")]
    pub(super) original_destination_connection_id: ConnectionId,
    #[getset(get_copy = "pub")]
    pub(super) retry_source_connection_id: Option<ConnectionId>,
    #[getset(get_copy = "pub")]
    pub(super) preferred_address: Option<PreferredAddress>,
    #[getset(get_copy = "pub")]
    pub(super) statelss_reset_token: Option<ResetToken>,
}

impl ServerParameters {
    /// Set the `original_destination_connection_id` transport parameter,
    /// which is the destination connection ID in the first Initial packet
    /// sent by the client.
    pub fn set_original_destination_connection_id(&mut self, cid: ConnectionId) -> &mut Self {
        self.original_destination_connection_id = cid;
        self
    }

    /// Set the `retry_source_connection_id` transport parameter,
    /// which is the srouce connection ID in the Retry packet,
    /// if the server decides to send a Retry packet to the client.
    pub fn set_retry_source_connection_id(&mut self, cid: ConnectionId) -> &mut Self {
        self.retry_source_connection_id = Some(cid);
        self
    }

    /// Set the `preferred_address` transport parameter,
    /// if the server wants the client to migrate to a new server address
    ///  at the end of the handshake.
    ///
    /// See [prefered-address](https://datatracker.ietf.org/doc/html/rfc9000#preferred-address)
    /// for more information.
    pub fn set_preferred_address(&mut self, addr: PreferredAddress) -> &mut Self {
        self.preferred_address = Some(addr);
        self
    }

    /// Set the `stateless_reset_token` transport parameter,
    /// which is used in verifying a stateless reset.
    ///
    /// See [stateless-reset](https://datatracker.ietf.org/doc/html/rfc9000#stateless-reset)
    /// for more information.
    pub fn set_statelss_reset_token(&mut self, token: ResetToken) -> &mut Self {
        self.statelss_reset_token = Some(token);
        self
    }
}

/// Parse server transport parameters from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
///
/// As a client, it will parse the server parameters
/// upon receiving the response Initial packet.
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
                    map(be_varint, |v| Duration::from_millis(v.into_inner())).parse(remain)?
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
            ParameterId::Value(_unknow) => {
                (input, _) = nom::bytes::streaming::take(len.into_inner())(remain)?
            }
        }
    }
    Ok((input, ()))
}

/// A [`bytes::BufMut`] extension trait, make buffer more friendly
/// to write server parameters.
pub trait WriteServerParameters: WriteCommonParameters {
    /// Write a reset token parameter with its patameter id.
    fn put_reset_token_parameter(&mut self, id: ParameterId, token: &ResetToken);

    /// Write a preferred address parameter with its patameter id.
    fn put_preferred_address_parameter(&mut self, id: ParameterId, addr: &PreferredAddress);

    /// Write all server parameters to the buffer.
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

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn test_common_parameters_default() {
        let params = CommonParameters::default();
        assert_eq!(params.max_idle_timeout(), Duration::ZERO);
        assert_eq!(params.max_udp_payload_size().into_inner(), 65527);
        assert_eq!(params.max_datagram_frame_size().into_inner(), 65535);
        assert_eq!(params.ack_delay_exponent().into_inner(), 3);
        assert_eq!(params.max_ack_delay().into_inner(), 25);
        assert!(!params.disable_active_migration());
        assert_eq!(params.active_connection_id_limit().into_inner(), 2);
    }

    #[test]
    fn test_common_parameters_setters() {
        let mut params = CommonParameters::default();
        params.set_max_udp_payload_size(1500);
        params.set_ack_delay_exponent(10);
        params.set_max_ack_delay(100);
        params.set_active_connection_id_limit(4);
        params.set_initial_max_streams_bidi(100);
        params.set_initial_max_streams_uni(50);

        assert_eq!(params.max_udp_payload_size().into_inner(), 1500);
        assert_eq!(params.ack_delay_exponent().into_inner(), 10);
        assert_eq!(params.max_ack_delay().into_inner(), 100);
        assert_eq!(params.active_connection_id_limit().into_inner(), 4);
        assert_eq!(params.initial_max_streams_bidi().into_inner(), 100);
        assert_eq!(params.initial_max_streams_uni().into_inner(), 50);
    }

    #[test]
    #[should_panic(expected = "Values below 1200 are invalid")]
    fn test_invalid_max_udp_payload_size() {
        let mut params = CommonParameters::default();
        params.set_max_udp_payload_size(1000);
    }

    #[test]
    #[should_panic(expected = "Values above 20 are invalid")]
    fn test_invalid_ack_delay_exponent() {
        let mut params = CommonParameters::default();
        params.set_ack_delay_exponent(21);
    }

    #[test]
    fn test_write_common_parameters() {
        let mut buf = Vec::new();
        let params = CommonParameters::default();
        buf.put_common_parameters(&params);
        assert!(!buf.is_empty());
        assert_eq!(
            buf,
            vec![
                1, 1, 0, // max_idle_timeout
                3, 4, 128, 0, 255, 247, // max_udp_payload_size
                4, 1, 0, // initial_max_data
                5, 1, 0, // initial_max_stream_data_bidi_local
                6, 1, 0, // initial_max_stream_data_bidi_remote
                7, 1, 0, // initial_max_stream_data_uni
                8, 1, 0, // initial_max_streams_bidi
                9, 1, 0, // initial_max_streams_uni
                10, 1, 3, // ack_delay_exponent
                11, 1, 25, // max_ack_delay
                14, 1, 2, // active_connection_id_limit
                15, 0, // initial_source_connection_id
                32, 4, 128, 0, 255, 255 // max_datagram_frame_size
            ]
        );
    }

    #[test]
    fn test_server_parameters() {
        let mut params = ServerParameters::default();
        let initial_scid = ConnectionId::from_slice("test_scid".as_bytes());
        let retry_scid = ConnectionId::from_slice("retry_scid".as_bytes());
        let token = ResetToken::default();
        let prefered_addr = PreferredAddress::new(
            "127.0.0.1:8080".parse().unwrap(),
            "[::1]:8081".parse().unwrap(),
            ConnectionId::from_slice(&[1, 2, 3, 4]),
            ResetToken::new(&[0; 16]),
        );

        params.set_original_destination_connection_id(initial_scid);
        params.set_retry_source_connection_id(retry_scid);
        params.set_statelss_reset_token(token);
        params.set_preferred_address(prefered_addr);

        assert_eq!(params.original_destination_connection_id, initial_scid);
        assert_eq!(params.retry_source_connection_id(), Some(retry_scid));
        assert_eq!(params.statelss_reset_token(), Some(token));
        assert_eq!(params.preferred_address(), Some(prefered_addr));
    }

    #[test]
    fn test_write_server_parameters() {
        let mut buf = Vec::new();
        let params = ServerParameters::default();
        buf.put_server_parameters(&params);
        assert_eq!(
            buf,
            vec![
                1, 1, 0, // max_idle_timeout
                3, 4, 128, 0, 255, 247, // max_udp_payload_size
                4, 1, 0, // initial_max_data
                5, 1, 0, // initial_max_stream_data_bidi_local
                6, 1, 0, // initial_max_stream_data_bidi_remote
                7, 1, 0, // initial_max_stream_data_uni
                8, 1, 0, // initial_max_streams_bidi
                9, 1, 0, // initial_max_streams_uni
                10, 1, 3, // ack_delay_exponent
                11, 1, 25, // max_ack_delay
                14, 1, 2, // active_connection_id_limit
                15, 0, // initial_source_connection_id
                32, 4, 128, 0, 255, 255, // max_datagram_frame_size
                0, 0 // original_destination_connection_id
            ]
        );
    }

    #[test]
    fn test_client_parameters() {
        let mut buf = Vec::new();
        let params = ClientParameters::default();
        buf.put_client_parameters(&params);
        assert_eq!(
            buf,
            vec![
                1, 1, 0, // max_idle_timeout
                3, 4, 128, 0, 255, 247, // max_udp_payload_size
                4, 1, 0, // initial_max_data
                5, 1, 0, // initial_max_stream_data_bidi_local
                6, 1, 0, // initial_max_stream_data_bidi_remote
                7, 1, 0, // initial_max_stream_data_uni
                8, 1, 0, // initial_max_streams_bidi
                9, 1, 0, // initial_max_streams_uni
                10, 1, 3, // ack_delay_exponent
                11, 1, 25, // max_ack_delay
                14, 1, 2, // active_connection_id_limit
                15, 0, // initial_source_connection_id
                32, 4, 128, 0, 255, 255 // max_datagram_frame_size
            ]
        );
    }

    #[test]
    fn test_parse_server_parameters() {
        let mut params = ServerParameters::default();
        let empty_input = &[
            1, 1, 0, // max_idle_timeout
            3, 4, 128, 0, 255, 247, // max_udp_payload_size
            4, 1, 0, // initial_max_data
            5, 1, 0, // initial_max_stream_data_bidi_local
            6, 1, 0, // initial_max_stream_data_bidi_remote
            7, 1, 0, // initial_max_stream_data_uni
            8, 1, 8, // initial_max_streams_bidi
            9, 1, 2, // initial_max_streams_uni
            10, 1, 3, // ack_delay_exponent
            11, 1, 25, // max_ack_delay
            14, 1, 2, // active_connection_id_limit
            15, 0, // initial_source_connection_id
            32, 4, 128, 0, 255, 255, // max_datagram_frame_size
            0, 0, // original_destination_connection_id
        ];
        let result = be_server_parameters(empty_input, &mut params);
        assert!(result.is_ok());
        assert_eq!(params.initial_max_streams_bidi().into_inner(), 8);
        assert_eq!(params.initial_max_streams_uni().into_inner(), 2);
    }

    #[test]
    fn test_parse_client_parameters() {
        let mut params = ClientParameters::default();
        let empty_input = &[
            1, 1, 0, // max_idle_timeout
            3, 4, 128, 0, 255, 247, // max_udp_payload_size
            4, 1, 0, // initial_max_data
            5, 1, 0, // initial_max_stream_data_bidi_local
            6, 1, 0, // initial_max_stream_data_bidi_remote
            7, 1, 0, // initial_max_stream_data_uni
            8, 1, 0, // initial_max_streams_bidi
            9, 1, 0, // initial_max_streams_uni
            10, 1, 3, // ack_delay_exponent
            11, 1, 60, // max_ack_delay
            14, 1, 10, // active_connection_id_limit
            15, 0, // initial_source_connection_id
            32, 4, 128, 0, 255, 255, // max_datagram_frame_size
        ];
        let result = be_client_parameters(empty_input, &mut params);
        assert!(result.is_ok());
        assert_eq!(params.max_ack_delay().into_inner(), 60);
        assert_eq!(params.active_connection_id_limit().into_inner(), 10);
    }
}
