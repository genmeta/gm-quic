use std::{collections::HashMap, fmt::Debug, time::Duration};

use derive_more::AsRef;

use super::GeneralParameters;
use crate::{
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::FrameType,
    param::{
        ParameterId, ParameterValue, PreferredAddress, StoreParameter, StoreParameterExt,
        be_parameter,
    },
    token::ResetToken,
    varint::VarInt,
};

fn parameter_error(id: ParameterId, ne: impl std::fmt::Display) -> QuicError {
    QuicError::new(
        ErrorKind::TransportParameter,
        FrameType::Crypto.into(),
        format!("parameter 0x{id:x}: {ne}"),
    )
}

macro_rules! parameters {
    (
        $(#[$set_attr:meta])*
        $set_vis:vis struct $set:ident { $(
            $id:ident: $id_ty:ident $(.$cast:ident() in $bound:expr)? => {
                $(#[$setter_attr:meta])*
                setter = $setter_name:ident,
                $(#[$getter_attr:meta])*
                getter = $getter_name:ident $(or $default:expr)?
            }
        )* }
    ) => {
        $(#[$set_attr])*
        $set_vis struct $set(HashMap<ParameterId, ParameterValue>);

        const _: () = {
            parameters! {
                @general($set)
                { $(
                    $id: $id_ty $(.$cast() in $bound)? => {
                        setter = $setter_name,
                        getter = $getter_name $(or $default)?
                    }
                )* }
            }

            $( parameters! {
                @methods($set)
                    $id: $id_ty => {
                    $(#[$setter_attr])*
                    setter = $setter_name,
                    $(#[$getter_attr])*
                    getter = $getter_name $(or $default)?
                }
            } )*
        };


    };
    (@general($set:ident)
        { $(
            $id:ident: $id_ty:ident $(.$cast:ident() in $bound:expr)? => {
                setter = $setter_name:ident,
                getter = $getter_name:ident $(or $default:expr)?
            }
        )* }
    ) => {
        impl StoreParameter for $set {
            fn get(&self, id: ParameterId) -> Option<ParameterValue> {
                self.0.get(&id).cloned().or_else(|| {
                    match id {
                        $( $( ParameterId::$id => { Some($default.into()) } )? )*
                        _ => None
                    }
                })
            }

            fn set(&mut self, id: ParameterId, value: ParameterValue) -> Result<(), QuicError>{
                match (id, value) {
                    $( (ParameterId::$id, value) => {
                        let value = $id_ty::try_from(value).map_err(|_| parameter_error(id, "Invalid parameter value: type unmatch"))?;
                        $( if !$bound.contains(&value.$cast()) {
                            return Err(parameter_error(id, format!("Invalid parameter value: out of bound {:?}", $bound)).into());
                        } )?
                        self.0.insert(id, value.into());
                    } )*
                    (ParameterId::Value(id), ParameterValue::Bytes(value)) => {
                        self.0.insert(ParameterId::Value(id), ParameterValue::Bytes(value));
                    }
                    _ => return Err(parameter_error(id, "Invalid parameter value: type unmatch").into()),
                }
                Ok(())
            }

            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }
    };
    (@methods($set:ident)
        $id:ident: $id_ty:ident  => {
            $(#[$setter_attr:meta])*
            setter = $setter_name:ident,
            $(#[$getter_attr:meta])*
            getter = $getter_name:ident $(or $default:expr)?
        }
    ) => {
        parameters! {
            @setter($set)
            $id: $id_ty => {
                $(#[$setter_attr])*
                setter = $setter_name
            }
        }

        parameters! {
            @getter($set)
            $id: $id_ty => {
                $(#[$getter_attr])*
                getter = $getter_name $(or $default)?
            }
        }
    };
    // getter with default
    (@getter($set:ident)
        $id:ident: $id_ty:ident  => {
            $(#[$getter_attr:meta])*
            getter = $getter_name:ident or $default:expr
        }
    ) => {
        impl $set {
            $(#[$getter_attr])*
            pub fn $getter_name(&self) -> $id_ty {
                self.get_as::<$id_ty>(ParameterId::$id).expect("default value shuold be got")
            }
        }
    };
    // getter without default
    (@getter($set:ident)
        $id:ident: $id_ty:ident  => {
            $(#[$getter_attr:meta])*
            getter = $getter_name:ident
        }
    ) => {
        impl $set {
            $(#[$getter_attr])*
            pub fn $getter_name(&self) -> Option<$id_ty> {
                self.get_as::<$id_ty>(ParameterId::$id)
            }
        }
    };
    // setter
    (@setter($set:ident)
        $id:ident: $id_ty:ident  => {
            $(#[$setter_attr:meta])*
            setter = $setter_name:ident
        }
    ) => {
        impl $set {
            $(#[$setter_attr])*
            pub fn $setter_name(&mut self, value: impl Into<$id_ty>) {
                self.set_as::<$id_ty>(ParameterId::$id, value.into()).expect("set parameter should be ok");
            }
        }
    };
}

fn must_be_exist(id: ParameterId) -> ParameterValue {
    unreachable!("parameter 0x{id:x} must be exist");
}

parameters! {
    #[derive(Default, Debug, Clone, AsRef)]
    pub struct ClientParameters {
        MaxIdleTimeout: Duration => {
            setter = set_max_idle_timeout,
            getter = max_idle_timeout or Duration::ZERO
        }
        MaxUdpPayloadSize: VarInt .into_inner() in 1200..=65527 => {
            setter = set_max_udp_payload_size,
            getter = max_udp_payload_size or VarInt::from_u32(65527)
        }
        MaxDatagramFrameSize: VarInt .into_inner() in 8..=65535 => {
            setter = set_max_datagram_frame_size,
            getter = max_datagram_frame_size or VarInt::from_u32(0)
        }
        AckDelayExponent: VarInt .into_inner() in 0..=20 => {
            setter = set_ack_delay_exponent,
            getter = ack_delay_exponent or VarInt::from_u32(3)
        }
        MaxAckDelay: Duration .as_millis() in 0..=(1 << 14) => {
            setter = set_max_ack_delay,
            getter = max_ack_delay or Duration::from_millis(25)
        }
        DisableActiveMigration: bool => {
            setter = set_disable_active_migration,
            getter = disable_active_migration or false
        }
        ActiveConnectionIdLimit: VarInt .into_inner() in 2..=u64::MAX => {
            setter = set_active_connection_id_limit,
            getter = active_connection_id_limit or VarInt::from_u32(2)
        }
        InitialMaxData: VarInt => {
            setter = set_initial_max_data,
            getter = initial_max_data or VarInt::default()
        }
        InitialMaxStreamDataBidiLocal: VarInt => {
            setter = set_initial_max_stream_data_bidi_local,
            getter = initial_max_stream_data_bidi_local or VarInt::default()
        }
        InitialMaxStreamDataBidiRemote: VarInt => {
            setter = set_initial_max_stream_data_bidi_remote,
            getter = initial_max_stream_data_bidi_remote or VarInt::default()
        }
        InitialMaxStreamDataUni: VarInt => {
            setter = set_initial_max_stream_data_uni,
            getter = initial_max_stream_data_uni or VarInt::default()
        }
        InitialMaxStreamsBidi: VarInt => {
            setter = set_initial_max_streams_bidi,
            getter = initial_max_streams_bidi or VarInt::default()
        }
        InitialMaxStreamsUni: VarInt => {
            setter = set_initial_max_streams_uni,
            getter = initial_max_streams_uni or VarInt::default()
        }
        InitialSourceConnectionId: ConnectionId => {
            setter = set_initial_source_connection_id,
            getter = initial_source_connection_id or must_be_exist(ParameterId::InitialSourceConnectionId)
        }
        GreaseQuicBit: bool => {
            setter = set_grease_quic_bit,
            getter = grease_quic_bit or false
        }
    }
}

pub fn be_client_parameters(mut input: &[u8]) -> Result<ClientParameters, QuicError> {
    fn map_nom_error(ne: impl ToString) -> QuicError {
        QuicError::new(
            ErrorKind::TransportParameter,
            FrameType::Crypto.into(),
            ne.to_string(),
        )
    }
    let mut params = ClientParameters::default();
    while !input.is_empty() {
        let (id, value);
        (input, (id, value)) = be_parameter(input).map_err(map_nom_error)?;
        params.set(id, value)?;
    }

    fn must_exist(id: ParameterId) -> QuicError {
        tracing::error!("   Cause by: validating parameters");
        parameter_error(id, "must exist in ClientParameters")
    }

    for id in [ParameterId::InitialSourceConnectionId] {
        if !params.0.contains_key(&id) {
            return Err(must_exist(id));
        }
    }

    fn must_not_exist(id: ParameterId) -> QuicError {
        tracing::error!("   Cause by: validating parameters");
        parameter_error(id, "should not exist in ClientParameters")
    }

    for id in [
        ParameterId::OriginalDestinationConnectionId,
        ParameterId::RetrySourceConnectionId,
        ParameterId::StatelssResetToken,
        ParameterId::PreferredAddress,
    ] {
        if params.0.contains_key(&id) {
            return Err(must_not_exist(id));
        }
    }

    Ok(params)
}

parameters! {
    #[derive(Default, Debug, Clone, AsRef)]
    pub struct ServerParameters {
        OriginalDestinationConnectionId: ConnectionId => {
            setter = set_original_destination_connection_id,
            getter = original_destination_connection_id or must_be_exist(ParameterId::OriginalDestinationConnectionId)
        }
        MaxIdleTimeout: Duration => {
            setter = set_max_idle_timeout,
            getter = max_idle_timeout or Duration::ZERO
        }
        StatelssResetToken: ResetToken => {
            setter = set_statelss_reset_token,
            getter = statelss_reset_token
        }
        MaxUdpPayloadSize: VarInt .into_inner() in 1200..=65527 => {
            setter = set_max_udp_payload_size,
            getter = max_udp_payload_size or VarInt::from_u32(65527)
        }
        InitialMaxData: VarInt => {
            setter = set_initial_max_data,
            getter = initial_max_data or VarInt::default()
        }
        InitialMaxStreamDataBidiLocal: VarInt => {
            setter = set_initial_max_stream_data_bidi_local,
            getter = initial_max_stream_data_bidi_local or VarInt::default()
        }
        InitialMaxStreamDataBidiRemote: VarInt => {
            setter = set_initial_max_stream_data_bidi_remote,
            getter = initial_max_stream_data_bidi_remote or VarInt::default()
        }
        InitialMaxStreamDataUni: VarInt => {
            setter = set_initial_max_stream_data_uni,
            getter = initial_max_stream_data_uni or VarInt::default()
        }
        InitialMaxStreamsBidi: VarInt => {
            setter = set_initial_max_streams_bidi,
            getter = initial_max_streams_bidi or VarInt::default()
        }
        InitialMaxStreamsUni: VarInt => {
            setter = set_initial_max_streams_uni,
            getter = initial_max_streams_uni or VarInt::default()
        }
        AckDelayExponent: VarInt .into_inner() in 0..=20 => {
            setter = set_ack_delay_exponent,
            getter = ack_delay_exponent or VarInt::from_u32(3)
        }
        MaxAckDelay: Duration .as_millis() in 0..=(1 << 14) => {
            setter = set_max_ack_delay,
            getter = max_ack_delay or Duration::from_millis(25)
        }
        DisableActiveMigration: bool => {
            setter = set_disable_active_migration,
            getter = disable_active_migration or false
        }
        PreferredAddress: PreferredAddress => {
            setter = set_preferred_address,
            getter = preferred_address
        }
        ActiveConnectionIdLimit: VarInt .into_inner() in 2..=u64::MAX => {
            setter = set_active_connection_id_limit,
            getter = active_connection_id_limit or VarInt::from_u32(2)
        }
        InitialSourceConnectionId: ConnectionId => {
            setter = set_initial_source_connection_id,
            getter = initial_source_connection_id or must_be_exist(ParameterId::InitialSourceConnectionId)
        }
        RetrySourceConnectionId: ConnectionId => {
            setter = set_retry_source_connection_id,
            getter = retry_source_connection_id
        }
        MaxDatagramFrameSize: VarInt .into_inner() in 8..=65535 => {
            setter = set_max_datagram_frame_size,
            getter = max_datagram_frame_size or VarInt::from_u32(0)
        }
        GreaseQuicBit: bool => {
            setter = set_grease_quic_bit,
            getter = grease_quic_bit or false
        }
    }
}

pub fn be_server_parameters(mut input: &[u8]) -> Result<ServerParameters, QuicError> {
    fn map_nom_error(ne: impl ToString) -> QuicError {
        QuicError::new(
            ErrorKind::TransportParameter,
            FrameType::Crypto.into(),
            ne.to_string(),
        )
    }
    let mut params = ServerParameters::default();
    while !input.is_empty() {
        let (id, value);
        (input, (id, value)) = be_parameter(input).map_err(map_nom_error)?;
        params.set(id, value)?;
    }

    fn must_exist(id: ParameterId) -> QuicError {
        tracing::error!("   Cause by: validate parameters");
        parameter_error(id, "must exist in ServerParameters")
    }

    for id in [
        ParameterId::OriginalDestinationConnectionId,
        ParameterId::InitialSourceConnectionId,
    ] {
        if !params.0.contains_key(&id) {
            return Err(must_exist(id));
        }
    }

    Ok(params)
}

pub type RememberedParameters = GeneralParameters;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_parameters_default() {
        let params = ClientParameters::default();
        assert_eq!(params.max_idle_timeout(), Duration::ZERO);
        assert_eq!(params.max_udp_payload_size().into_inner(), 65527);
        assert_eq!(params.max_datagram_frame_size().into_inner(), 0);
        assert_eq!(params.ack_delay_exponent().into_inner(), 3);
        assert_eq!(params.max_ack_delay().as_millis(), 25);
        assert!(!params.disable_active_migration());
        assert_eq!(params.active_connection_id_limit().into_inner(), 2);
    }

    #[test]
    fn test_client_parameters_setters() {
        let mut params = ClientParameters::default();
        params.set_max_udp_payload_size(1500u32);
        params.set_ack_delay_exponent(10u32);
        params.set_max_ack_delay(Duration::from_millis(100));
        params.set_active_connection_id_limit(4u32);
        params.set_initial_max_streams_bidi(100u32);
        params.set_initial_max_streams_uni(50u32);

        assert_eq!(params.max_udp_payload_size().into_inner(), 1500);
        assert_eq!(params.ack_delay_exponent().into_inner(), 10);
        assert_eq!(params.max_ack_delay().as_millis(), 100);
        assert_eq!(params.active_connection_id_limit().into_inner(), 4);
        assert_eq!(params.initial_max_streams_bidi().into_inner(), 100);
        assert_eq!(params.initial_max_streams_uni().into_inner(), 50);
    }

    #[test]
    #[should_panic(expected = "Invalid parameter value: out of bound 1200..=65527")]
    fn test_invalid_max_udp_payload_size() {
        let mut params = ClientParameters::default();
        params.set_max_udp_payload_size(1000u32);
    }

    #[test]
    #[should_panic(expected = "Invalid parameter value: out of bound 0..=20")]
    fn test_invalid_ack_delay_exponent() {
        let mut params = ClientParameters::default();
        params.set_ack_delay_exponent(21u32);
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

        params.set_original_destination_connection_id(origin_dcid);
        params.set_retry_source_connection_id(retry_scid);
        params.set_statelss_reset_token(token);
        params.set_preferred_address(prefered_addr);

        assert_eq!(params.original_destination_connection_id(), origin_dcid);
        assert_eq!(params.retry_source_connection_id(), Some(retry_scid));
        assert_eq!(params.statelss_reset_token(), Some(token));
        assert_eq!(params.preferred_address(), Some(prefered_addr));
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
        assert_eq!(params.initial_max_streams_bidi().into_inner(), 8);
        assert_eq!(params.initial_max_streams_uni().into_inner(), 2);
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
        assert_eq!(params.max_ack_delay().as_millis(), 60);
        assert_eq!(params.active_connection_id_limit().into_inner(), 10);
    }
}
