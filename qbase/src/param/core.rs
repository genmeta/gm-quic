use std::fmt::Debug;

use derive_more::{AsRef, From, Into, TryInto};

use super::GeneralParameters;
use crate::{
    error::{ErrorKind, QuicError},
    frame::FrameType,
    param::{ParameterFlags, ParameterId, ParameterValue, be_parameter},
    varint::VarInt,
};

fn parameter_error(id: ParameterId, ne: impl std::fmt::Display) -> QuicError {
    QuicError::new(
        ErrorKind::TransportParameter,
        FrameType::Crypto.into(),
        format!("parameter 0x{id:x}: {ne}"),
    )
}

fn map_nom_error(ne: impl ToString) -> QuicError {
    QuicError::new(
        ErrorKind::TransportParameter,
        FrameType::Crypto.into(),
        ne.to_string(),
    )
}

fn must_exist(id: ParameterId) -> QuicError {
    tracing::error!("   Cause by: validating parameters");
    parameter_error(id, "must exist")
}

#[derive(Debug, From, TryInto)]
pub enum PeerParameters {
    Clinet(ClientParameters),
    Server(ServerParameters),
}

impl AsRef<GeneralParameters> for PeerParameters {
    fn as_ref(&self) -> &GeneralParameters {
        match self {
            PeerParameters::Clinet(params) => &params.0,
            PeerParameters::Server(params) => &params.0,
        }
    }
}

#[derive(Default, Debug, Clone, Into, AsRef, PartialEq)]
pub struct ClientParameters(GeneralParameters);

impl ClientParameters {
    #[inline]
    pub fn get(&self, id: ParameterId) -> Option<ParameterValue> {
        self.0.get(id)
    }

    #[inline]
    pub fn get_as<V>(&self, id: ParameterId) -> Option<V>
    where
        V: TryFrom<ParameterValue>,
        <V as TryFrom<ParameterValue>>::Error: Debug,
    {
        self.0.get_as(id)
    }

    #[inline]
    pub fn set<V>(&mut self, id: ParameterId, value: V) -> Result<(), QuicError>
    where
        V: Into<ParameterValue>,
    {
        if id.flags().contains(ParameterFlags::NOT_CLIENT) {
            return Err(parameter_error(id, "not allowed in client parameters"));
        }
        self.0.set(id, value)
    }

    #[inline]
    pub fn contains(&self, id: ParameterId) -> bool {
        self.0.contains(id)
    }
}

pub fn be_client_parameters(mut input: &[u8]) -> Result<ClientParameters, QuicError> {
    let mut params = ClientParameters::default();
    while !input.is_empty() {
        let (id, value);
        (input, (id, value)) = be_parameter(input).map_err(map_nom_error)?;
        params.set(id, value)?;
    }

    if let Some(id) = ParameterId::KNOWNS
        .iter()
        .filter(|id| id.flags().contains(ParameterFlags::CLIENT_REQUIRED))
        .find(|id| !params.contains(**id))
    {
        return Err(must_exist(*id));
    }

    Ok(params)
}

#[derive(Default, Debug, Clone, Into, AsRef, PartialEq)]
pub struct ServerParameters(GeneralParameters);

impl ServerParameters {
    #[inline]
    pub fn get(&self, id: ParameterId) -> Option<ParameterValue> {
        self.0.get(id)
    }

    #[inline]
    pub fn get_as<V>(&self, id: ParameterId) -> Option<V>
    where
        V: TryFrom<ParameterValue>,
        <V as TryFrom<ParameterValue>>::Error: Debug,
    {
        self.0.get_as(id)
    }

    #[inline]
    pub fn set<V>(&mut self, id: ParameterId, value: V) -> Result<(), QuicError>
    where
        V: Into<ParameterValue>,
    {
        if id.flags().contains(ParameterFlags::NOT_SERVER) {
            return Err(parameter_error(id, "not allowed in client parameters"));
        }
        self.0.set(id, value)
    }

    #[inline]
    pub fn contains(&self, id: ParameterId) -> bool {
        self.0.contains(id)
    }
}

pub fn be_server_parameters(mut input: &[u8]) -> Result<ServerParameters, QuicError> {
    let mut params = ServerParameters::default();
    while !input.is_empty() {
        let (id, value);
        (input, (id, value)) = be_parameter(input).map_err(map_nom_error)?;
        params.set(id, value)?;
    }

    if let Some(id) = ParameterId::KNOWNS
        .iter()
        .filter(|id| id.flags().contains(ParameterFlags::SERVER_REQUIRED))
        .find(|id| !params.contains(**id))
    {
        return Err(must_exist(*id));
    }

    Ok(params)
}

#[derive(Debug, Into)]
pub struct RememberedParameters(GeneralParameters);

impl RememberedParameters {
    #[inline]
    pub fn get(&self, id: ParameterId) -> Option<ParameterValue> {
        if id.flags().contains(ParameterFlags::NOT_RESUME) {
            return id.default_value();
        }
        self.0.get(id)
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
    pub fn contains(&self, id: ParameterId) -> bool {
        self.0.contains(id)
    }

    pub fn is_0rtt_accepted(&self, server_params: &ServerParameters) -> bool {
        ParameterId::KNOWNS
            .iter()
            .filter(|id| id.flags().contains(ParameterFlags::NOT_REDUCE))
            .all(|&id| {
                match (
                    self.get_as::<VarInt>(id),
                    server_params.get_as::<VarInt>(id),
                ) {
                    (Some(old_value), Some(new_value)) => old_value <= new_value,
                    _ => unreachable!("NOT_REDUCE parameters have default values"),
                }
            })
    }
}

impl From<ServerParameters> for RememberedParameters {
    fn from(value: ServerParameters) -> Self {
        RememberedParameters(value.0)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{cid::ConnectionId, param::PreferredAddress, token::ResetToken, varint::VarInt};

    #[test]
    fn test_client_parameters_default() {
        let params = ClientParameters::default();
        assert_eq!(
            params
                .get_as::<Duration>(ParameterId::MaxIdleTimeout)
                .unwrap(),
            Duration::ZERO
        );
        assert_eq!(
            params
                .get_as::<VarInt>(ParameterId::MaxUdpPayloadSize)
                .unwrap()
                .into_inner(),
            65527
        );
        assert_eq!(
            params
                .get_as::<VarInt>(ParameterId::MaxDatagramFrameSize)
                .unwrap_or_default()
                .into_inner(),
            0
        );
        assert_eq!(
            params
                .get_as::<VarInt>(ParameterId::AckDelayExponent)
                .unwrap_or_default()
                .into_inner(),
            3
        );
        assert_eq!(
            params
                .get_as::<Duration>(ParameterId::MaxAckDelay)
                .unwrap_or_default()
                .as_millis(),
            25
        );
        assert!(
            !params
                .get_as::<bool>(ParameterId::DisableActiveMigration)
                .unwrap_or_default()
        );
        assert_eq!(
            params
                .get_as::<VarInt>(ParameterId::ActiveConnectionIdLimit)
                .unwrap_or_default()
                .into_inner(),
            2
        );
    }

    #[test]
    fn test_client_parameters_setters() {
        let mut params = ClientParameters::default();
        params
            .set(ParameterId::MaxUdpPayloadSize, VarInt::from_u32(1500))
            .unwrap();
        params
            .set(ParameterId::AckDelayExponent, VarInt::from_u32(10))
            .unwrap();
        params
            .set(ParameterId::MaxAckDelay, Duration::from_millis(100))
            .unwrap();
        params
            .set(ParameterId::ActiveConnectionIdLimit, VarInt::from_u32(4))
            .unwrap();
        params
            .set(ParameterId::InitialMaxStreamsBidi, VarInt::from_u32(100))
            .unwrap();
        params
            .set(ParameterId::InitialMaxStreamsUni, VarInt::from_u32(50))
            .unwrap();

        assert_eq!(
            params
                .get_as::<VarInt>(ParameterId::MaxUdpPayloadSize)
                .unwrap()
                .into_inner(),
            1500
        );
        assert_eq!(
            params
                .get_as::<VarInt>(ParameterId::AckDelayExponent)
                .unwrap()
                .into_inner(),
            10
        );
        assert_eq!(
            params
                .get_as::<Duration>(ParameterId::MaxAckDelay)
                .unwrap()
                .as_millis(),
            100
        );
        assert_eq!(
            params
                .get_as::<VarInt>(ParameterId::ActiveConnectionIdLimit)
                .unwrap()
                .into_inner(),
            4
        );
        assert_eq!(
            params
                .get_as::<VarInt>(ParameterId::InitialMaxStreamsBidi)
                .unwrap()
                .into_inner(),
            100
        );
        assert_eq!(
            params
                .get_as::<VarInt>(ParameterId::InitialMaxStreamsUni)
                .unwrap()
                .into_inner(),
            50
        );
    }

    #[test]
    #[should_panic(expected = "Invalid parameter value: out of bound 1200..=65527")]
    fn test_invalid_max_udp_payload_size() {
        let mut params = ClientParameters::default();
        params
            .set(ParameterId::MaxUdpPayloadSize, VarInt::from_u32(1000))
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid parameter value: out of bound 0..=20")]
    fn test_invalid_ack_delay_exponent() {
        let mut params = ClientParameters::default();
        params
            .set(ParameterId::AckDelayExponent, VarInt::from_u32(30))
            .unwrap();
    }

    #[test]
    fn test_server_parameters() {
        let mut params = ServerParameters::default();
        let origin_dcid = ConnectionId::from_slice("origin_dcid".as_bytes());
        let retry_scid = ConnectionId::from_slice("retry_scid".as_bytes());
        let token = ResetToken::default();
        let prefered_addr = PreferredAddress::new(
            "127.0.0.1:8080".parse().unwrap(),
            "[::1]:8081".parse().unwrap(),
            ConnectionId::from_slice(&[1, 2, 3, 4]),
            ResetToken::new(&[0; 16]),
        );

        // params.set_original_destination_connection_id(origin_dcid);
        // params.set_retry_source_connection_id(retry_scid);
        // params.set_statelss_reset_token(token);
        // params.set_preferred_address(prefered_addr);
        params
            .set(ParameterId::OriginalDestinationConnectionId, origin_dcid)
            .unwrap();
        params
            .set(ParameterId::RetrySourceConnectionId, retry_scid)
            .unwrap();
        params.set(ParameterId::StatelessResetToken, token).unwrap();
        params
            .set(ParameterId::PreferredAddress, prefered_addr)
            .unwrap();

        assert_eq!(
            params
                .get_as::<ConnectionId>(ParameterId::OriginalDestinationConnectionId)
                .unwrap(),
            origin_dcid
        );
        assert_eq!(
            params
                .get_as::<ConnectionId>(ParameterId::RetrySourceConnectionId)
                .unwrap(),
            retry_scid
        );
        assert_eq!(
            params
                .get_as::<ResetToken>(ParameterId::StatelessResetToken)
                .unwrap(),
            token
        );
        assert_eq!(
            params
                .get_as::<PreferredAddress>(ParameterId::PreferredAddress)
                .unwrap(),
            prefered_addr
        );
    }

    #[test]
    fn test_parse_server_parameters() {
        let input = &[
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
        let params = be_server_parameters(input).unwrap();
        assert_eq!(
            params
                .get_as::<VarInt>(ParameterId::InitialMaxStreamsBidi)
                .unwrap()
                .into_inner(),
            8
        );
        assert_eq!(
            params
                .get_as::<VarInt>(ParameterId::InitialMaxStreamsUni)
                .unwrap()
                .into_inner(),
            2
        );
    }

    #[test]
    fn test_parse_client_parameters() {
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
        let params = be_client_parameters(empty_input).unwrap();
        assert_eq!(
            params.get_as::<Duration>(ParameterId::MaxAckDelay).unwrap(),
            Duration::from_millis(60)
        );
        assert_eq!(
            params
                .get_as::<VarInt>(ParameterId::ActiveConnectionIdLimit)
                .unwrap()
                .into_inner(),
            10
        );
    }
}
