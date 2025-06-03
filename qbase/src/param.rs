use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use crate::{
    cid::ConnectionId,
    error::{Error, ErrorKind, QuicError},
    frame::FrameType,
    sid::Role,
};

pub mod handy;
mod util;
pub use util::*;

mod core;
pub use core::*;

/// Requires that the connection IDs in the transport parameters of
/// the received Initial packet must match those used during the
/// connection establishment process.
///
/// For the Initial packet received by the server from the client,
/// the initial_source_connection_id in the client's Transport
/// parameters must match the source connection id in that Initial packet.
/// For the Initial packet received by the client from the server,
/// not only must the server's Transport parameter
/// initial_source_connection_id match the source connection id
/// in that Initial packet,
/// but also requires that the original_destination_connection_id matches the
/// destination connection id in the first packet sent by the client.
/// Specifically, if the server has responded with a Retry packet,
/// then the server's Transport parameter retry_source_connection_id
/// must match the source connection id in that Retry packet.
///
/// See [Authenticating Connection IDs](https://datatracker.ietf.org/doc/html/rfc9000#name-authenticating-connection-i)
/// of [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000)
/// for more details.
///
/// Whether client or server, after receiving the Initial packet from
/// the peer, these requirements must be set;
/// then after parsing the peer's Transport parameters, verify that
/// all these requirements are met.
/// If not met, it is considered a TransportParameters error.
#[derive(Debug, Clone, Copy)]
enum Requirements {
    Client {
        initial_scid: Option<ConnectionId>,
        retry_scid: Option<ConnectionId>,
        origin_dcid: ConnectionId,
    },
    Server {
        initial_scid: Option<ConnectionId>,
    },
}

/// Transport parameters for QUIC.
/// The transport parameters are used to negotiate the initial
/// settings of a QUIC connection.
///
/// They are exchanged in the Initial packets of the handshake,
/// including client and server transport parameters.
/// Client transport parameters and server transport parameters
/// exist independently and are not merged.
/// They each constrain the behavior of the remote peer.
///
/// For different roles, local transport parameters and remote
/// transport parameters differ.
/// For example, as a client, the local transport parameters
/// are client parameters, while remote transport parameters
/// are server parameters. The same applies to the server.
///
/// Note that client transport parameters and server transport
/// parameters are different, as some transport parameters can
/// only appear in server transport parameters.
/// Therefore, for a QUIC connection, the transport parameter
/// sets for both ends are defined as follows.
#[derive(Debug)]
pub struct Parameters {
    state: u8,
    client: Arc<ClientParameters>,
    server: Arc<ServerParameters>,
    remembered: Option<RememberedParameters>,
    requirements: Requirements,
    wakers: Vec<Waker>,
}

impl Parameters {
    const CLIENT_READY: u8 = 1;
    const SERVER_READY: u8 = 2;

    /// Creates a new client transport parameters, with the client
    /// parameters and remembered server parameters if exist.
    ///
    /// It will wait for the server transport parameters to be
    /// received and parsed.
    fn new_client(
        client: ClientParameters,
        remembered: Option<RememberedParameters>,
        origin_dcid: ConnectionId,
    ) -> Self {
        Self {
            state: Self::CLIENT_READY,
            client: Arc::new(client),
            server: Arc::default(),
            remembered,
            requirements: Requirements::Client {
                origin_dcid,
                initial_scid: None,
                retry_scid: None,
            },
            wakers: Vec::with_capacity(2),
        }
    }

    /// Creates a new server transport parameters, with the server
    /// parameters.
    ///
    /// It will wait for the client transport parameters to be
    /// received and parsed.
    fn new_server(server: ServerParameters) -> Self {
        Self {
            state: Self::SERVER_READY,
            client: Arc::default(),
            server: Arc::new(server),
            remembered: None,
            requirements: Requirements::Server { initial_scid: None },
            wakers: Vec::with_capacity(2),
        }
    }

    fn role(&self) -> Role {
        match self.requirements {
            Requirements::Client { .. } => Role::Client,
            Requirements::Server { .. } => Role::Server,
        }
    }

    fn remembered(&self) -> Option<&RememberedParameters> {
        self.remembered.as_ref()
    }

    // fn set_retry_scid(&mut self, cid: ConnectionId) {
    //     assert_eq!(self.role(), Role::Server);
    //     self.server.set_retry_source_connection_id(cid);
    // }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.state == Self::CLIENT_READY | Self::SERVER_READY {
            Poll::Ready(())
        } else {
            self.wakers.push(cx.waker().clone());
            Poll::Pending
        }
    }

    fn is_remote_params_ready(&self) -> bool {
        self.state == Self::CLIENT_READY | Self::SERVER_READY
    }

    fn recv_remote_params(
        &mut self,
        params: &[u8],
        extra_auth: impl FnOnce(&dyn StoreParameter) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.state = Self::CLIENT_READY | Self::SERVER_READY;
        self.parse_and_validate_remote_params(params)?;
        // Because TLS and packet parsing are in parallel,
        // the scid of the peer end may not be set when the transmission parameters of the peer are obtained.
        // Therefore, if the scid of the other end is not set, authentication will not be performed first,
        // and authentication will be performed when it is set.
        if self.authenticate_cids()? {
            extra_auth(match self.role() {
                Role::Client => self.server.as_ref(),
                Role::Server => self.client.as_ref(),
            })?;
            self.state = Self::CLIENT_READY | Self::SERVER_READY;
            self.wake_all();
            return Ok(());
        }

        Ok(())
    }

    fn wake_all(&mut self) {
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }

    fn parse_and_validate_remote_params(&mut self, input: &[u8]) -> Result<(), QuicError> {
        match self.role() {
            Role::Client => self.server = Arc::new(be_server_parameters(input)?),
            Role::Server => self.client = Arc::new(be_client_parameters(input)?),
        }
        Ok(())
    }

    fn initial_scid_from_peer_need_equal(&mut self, cid: ConnectionId) {
        let initial_scid = match &mut self.requirements {
            Requirements::Client { initial_scid, .. } => initial_scid,
            Requirements::Server { initial_scid } => initial_scid,
        };
        assert!(initial_scid.replace(cid).is_none());
    }

    fn retry_scid_from_server_need_equal(&mut self, cid: ConnectionId) {
        match &mut self.requirements {
            Requirements::Client { retry_scid, .. } => *retry_scid = Some(cid),
            Requirements::Server { .. } => panic!("server shuold never call this"),
        }
    }

    fn get_origin_dcid(&self) -> ConnectionId {
        match self.requirements {
            Requirements::Client { origin_dcid, .. } => origin_dcid,
            Requirements::Server { .. } => self.server.original_destination_connection_id(),
        }
    }

    fn authenticate_cids(&self) -> Result<bool, QuicError> {
        fn param_error(reason: &'static str) -> QuicError {
            QuicError::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto.into(),
                reason,
            )
        }

        // Because TLS and packet parsing are in parallel,
        // the scid of the peer end may not be set when the transmission parameters of the peer are obtained.
        // Therefore, if the scid of the other end is not set, authentication will not be performed first,
        // and authentication will be performed when it is set.
        match self.requirements {
            Requirements::Client {
                initial_scid,
                retry_scid: _,
                origin_dcid,
            } => {
                // Because TLS and packet parsing are in parallel,
                // the scid of the peer end may not be set when the transmission parameters of the peer are obtained.
                // Therefore, if the scid of the other end is not set, authentication will not be performed first,
                // and authentication will be performed when it is set.
                let Some(initial_scid) = initial_scid else {
                    return Ok(false);
                };
                if self.server.initial_source_connection_id() != initial_scid {
                    return Err(param_error(
                        "Initial Source Connection ID from server mismatch",
                    ));
                }
                // 并不正确，要和intiial_scid一样地去验证
                // if self.server.retry_source_connection_id() != retry_scid {
                //     return Err(param_error("Retry Source Connection ID mismatch"));
                // }
                if self.server.original_destination_connection_id() != origin_dcid {
                    return Err(param_error("Original Destination Connection ID mismatch"));
                }
                Ok(true)
            }
            Requirements::Server { initial_scid } => {
                let Some(initial_scid) = initial_scid else {
                    return Ok(false);
                };
                if self.client.initial_source_connection_id() != initial_scid {
                    return Err(param_error(
                        "Initial Source Connection ID from client mismatch",
                    ));
                }
                Ok(true)
            }
        }
    }
}

/// Shared transport parameter sets for both endpoints.
///
/// The local transport parameters are set initially, while
/// the remote transport parameters must wait until they are
/// received through network transmission and can be parsed.
/// After parsing, the peer parameters must be immediately
/// verified to ensure they meet the requirements and validity
/// checks.
///
/// Note that a connection error may occur before receiving
/// the remote transport parameters, such as network unreachable.
/// In such cases, the entire connection parameters will be
/// converted into an error state.
#[derive(Debug, Clone)]
pub struct ArcParameters(Arc<Mutex<Result<Parameters, Error>>>);

impl ArcParameters {
    /// Creates a new client transport parameters, with the client
    /// parameters and remembered server parameters if exist.
    ///
    /// It will wait for the server transport parameters to be
    /// received and parsed.
    pub fn new_client(
        client: ClientParameters,
        remembered: Option<RememberedParameters>,
        origin_dcid: ConnectionId,
    ) -> Self {
        Self(Arc::new(Mutex::new(Ok(Parameters::new_client(
            client,
            remembered,
            origin_dcid,
        )))))
    }

    /// Creates a new server transport parameters, with the server
    /// parameters.
    ///
    /// It will wait for the client transport parameters to be
    /// received and parsed.
    pub fn new_server(server: ServerParameters) -> Self {
        Self(Arc::new(Mutex::new(Ok(Parameters::new_server(server)))))
    }

    pub fn get_local(&self) -> Result<Arc<dyn StoreParameter + Send + Sync>, Error> {
        match self.0.lock().unwrap().as_ref() {
            Ok(params) => Ok(match params.role() {
                Role::Client => params.client.clone(),
                Role::Server => params.server.clone(),
            }),
            Err(e) => Err(e.clone()),
        }
    }

    /// Get the local transport parameter by id.
    ///
    /// Returns Err if some connection error occurred, or the parameter not exist
    pub fn get_local_as<V>(&self, id: ParameterId) -> Result<V, Error>
    where
        V: TryFrom<ParameterValue>,
        <V as TryFrom<ParameterValue>>::Error: Debug,
    {
        match self.0.lock().unwrap().as_ref() {
            Ok(params) => match params.role() {
                Role::Client => params.client.get_as::<V>(id),
                Role::Server => params.server.get_as::<V>(id),
            }
            .ok_or_else(|| {
                QuicError::new(
                    ErrorKind::TransportParameter,
                    FrameType::Crypto.into(),
                    format!("access unknow parameter 0x{id:x}",),
                )
                .into()
            }),
            Err(e) => Err(e.clone()),
        }
    }

    pub async fn remote(&self) -> Result<Arc<dyn StoreParameter + Send + Sync>, Error> {
        std::future::poll_fn(|cx| match self.0.lock().unwrap().as_mut() {
            Ok(params) => params.poll_ready(cx).map(|()| {
                Ok(match params.role() {
                    Role::Client => params.server.clone() as Arc<dyn StoreParameter + Send + Sync>,
                    Role::Server => params.client.clone() as Arc<dyn StoreParameter + Send + Sync>,
                })
            }),
            Err(e) => Poll::Ready(Err(e.clone())),
        })
        .await
    }

    pub fn try_get_remote(&self) -> Result<Option<Arc<dyn StoreParameter + Send + Sync>>, Error> {
        match self.0.lock().unwrap().as_ref() {
            Ok(params) => Ok(params
                .is_remote_params_ready()
                .then(|| match params.role() {
                    Role::Client => params.server.clone() as Arc<dyn StoreParameter + Send + Sync>,
                    Role::Server => params.client.clone() as Arc<dyn StoreParameter + Send + Sync>,
                })),
            Err(e) => Err(e.clone()),
        }
    }

    /// Get the remote transport parameter by id.
    ///
    /// Returns Err if some connection error occurred, or the parameter not exist
    pub async fn get_remote_as<V>(&self, id: ParameterId) -> Result<V, Error>
    where
        V: TryFrom<ParameterValue>,
        <V as TryFrom<ParameterValue>>::Error: Debug,
    {
        std::future::poll_fn(|cx| match self.0.lock().unwrap().as_mut() {
            Ok(params) => params.poll_ready(cx).map(|()| {
                match params.role() {
                    Role::Client => params.server.get_as::<V>(id),
                    Role::Server => params.client.get_as::<V>(id),
                }
                .ok_or_else(|| {
                    QuicError::new(
                        ErrorKind::TransportParameter,
                        FrameType::Crypto.into(),
                        format!("access unknow parameter 0x{id:x}",),
                    )
                    .into()
                })
            }),
            Err(e) => Poll::Ready(Err(e.clone())),
        })
        .await
    }

    /// Returns the remembered server transport parameters if exist,
    /// which means the client connected the server, and stored the
    /// server transport parameters.
    ///
    /// It is meaningful only for the client, to send early data
    /// with 0Rtt packets before receving the server transport params.
    pub fn get_remebered_as<V>(&self, id: ParameterId) -> Result<Option<V>, Error>
    where
        V: TryFrom<ParameterValue>,
        <V as TryFrom<ParameterValue>>::Error: Debug,
    {
        let guard = self.0.lock().unwrap();
        let params = guard.as_ref().map_err(Clone::clone)?;
        Ok(params.remembered().and_then(|r| r.get_as(id)))
    }

    // /// Sets the retry source connection ID in the server
    // /// transport parameters.
    // ///
    // /// It is meaningful only for the client, because only
    // /// server can send the Retry packet.
    // pub fn set_retry_scid(&self, cid: ConnectionId) {
    //     let mut guard = self.0.lock().unwrap();
    //     if let Ok(params) = guard.deref_mut() {
    //         params.set_retry_scid(cid);
    //     }
    // }

    /// Gets the original destination connection ID of the connection.
    ///
    /// This value is chosen by the client and sent to the server, then
    /// the server will echo it back to the client.
    ///
    /// This value is well suited to be used to identify a connection.
    pub fn get_origin_dcid(&self) -> Result<ConnectionId, Error> {
        let guard = self.0.lock().unwrap();
        let params = guard.as_ref().map_err(Clone::clone)?;
        Ok(params.get_origin_dcid())
    }

    /// Load the local transport parameters into the buffer, which
    /// will be send to the peer soon.
    pub fn load_local_params_into(&self, buf: &mut Vec<u8>) {
        let guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref() {
            match params.role() {
                Role::Client => buf.put_parameters(params.client.as_ref().as_ref()),
                Role::Server => buf.put_parameters(params.server.as_ref().as_ref()),
            }
        }
    }

    pub fn initial_scid_from_peer(&self) -> Result<Option<ConnectionId>, Error> {
        let guard = self.0.lock().unwrap();
        let parameters = guard.as_ref().map_err(Clone::clone)?;
        Ok(match parameters.requirements {
            Requirements::Client { initial_scid, .. } => initial_scid,
            Requirements::Server { initial_scid, .. } => initial_scid,
        })
    }

    /// No matter the client or server, after receiving the Initial
    /// packet from the peer, the initial_source_connection_id in
    /// the remote transport parameters must equal the source connection
    /// id in the received Initial packet.
    ///
    /// If the peer's transmission parameters have not been verified,
    /// it will be verified here. If verification fails, this method will
    /// return Err.
    pub fn initial_scid_from_peer_need_equal(&self, cid: ConnectionId) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.initial_scid_from_peer_need_equal(cid);
        }
    }

    /// After receiving the Retry packet from the server, the
    /// retry_source_connection_id in the server transport parameters
    /// must equal the source connection id in the Retry packet.
    pub fn retry_scid_from_server_need_equal(&self, cid: ConnectionId) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.retry_scid_from_server_need_equal(cid);
        }
    }

    /// Being called when the remote transport parameters are received.
    /// It will parse and check the remote transport parameters,
    /// and wake all the wakers waiting for the remote transport parameters
    /// if the remote transport parameters are valid.
    pub fn recv_remote_params(
        &self,
        bytes: &[u8],
        extra_auth: impl FnOnce(&dyn StoreParameter) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut guard = self.0.lock().unwrap();
        let params = guard.as_mut().map_err(|e| e.clone())?;
        // 避免外界拿到错误的参数
        match params.recv_remote_params(bytes, extra_auth) {
            Ok(remote_params) => Ok(remote_params),
            Err(error) => {
                params.wake_all();
                Err(error)
            }
        }
    }

    /// Returns true if the remote transport parameters have been received and authed.
    ///
    /// It is usually used to avoid processing remote transport parameters
    /// more than once.
    pub fn is_remote_params_ready(&self) -> bool {
        let guard = self.0.lock().unwrap();
        match guard.deref() {
            Ok(params) => params.is_remote_params_ready(),
            Err(_) => false,
        }
    }

    /// When some connection error occurred, convert this parameters
    /// into error state.
    pub fn on_conn_error(&self, error: &Error) {
        tracing::warn!(
            ?error,
            "connection error, convert parameters to error state"
        );
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.wake_all();
            *guard = Err(error.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::varint::VarInt;

    fn create_test_client_params() -> ClientParameters {
        let mut params = ClientParameters::default();
        params.set_initial_source_connection_id(ConnectionId::from_slice(b"client_test"));
        params
    }

    fn create_test_server_params() -> ServerParameters {
        let mut params = ServerParameters::default();
        params.set_initial_source_connection_id(ConnectionId::from_slice(b"server_test"));
        params.set_original_destination_connection_id(ConnectionId::from_slice(b"original"));
        params
    }

    #[test]
    fn test_parameters_new() {
        let client_params = create_test_client_params();
        let params =
            Parameters::new_client(client_params, None, ConnectionId::from_slice(b"odcid"));
        assert_eq!(params.role(), Role::Client);
        assert_eq!(params.state, Parameters::CLIENT_READY);

        let server_params = create_test_server_params();
        let params = Parameters::new_server(server_params);
        assert_eq!(params.role(), Role::Server);
        assert_eq!(params.state, Parameters::SERVER_READY);
    }

    #[test]
    fn test_authenticate_cids() {
        let client_params = create_test_client_params();

        let odcid = ConnectionId::from_slice(b"odcid");

        let mut params = Parameters::new_client(client_params, None, odcid);

        let server_cid = ConnectionId::from_slice(b"server_test");
        params.initial_scid_from_peer_need_equal(server_cid);

        params.server = Arc::new({
            let mut server_params = ServerParameters::default();
            server_params.set_initial_source_connection_id(server_cid);
            server_params.set_original_destination_connection_id(odcid);
            server_params
        });

        assert!(dbg!(params.authenticate_cids()).is_ok());
    }

    #[test]
    fn test_parameters_as_client() {
        let client_params = create_test_client_params();
        let arc_params =
            ArcParameters::new_client(client_params, None, ConnectionId::from_slice(b"odcid"));

        // Test local params
        let local = arc_params.get_local_as::<VarInt>(ParameterId::MaxUdpPayloadSize);
        assert!(matches!(local, Ok(value) if value.into_inner() >= 1200));

        // Test remembered params
        assert_eq!(
            arc_params.get_remebered_as::<VarInt>(ParameterId::MaxUdpPayloadSize),
            Ok(None)
        );

        // Test loading local params
        let mut buf = Vec::new();
        arc_params.load_local_params_into(&mut buf);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_validate_remote_params() {
        // Test invalid max_udp_payload_size
        let mut params = Parameters::new_server(create_test_server_params());
        let result = params.recv_remote_params(
            &[
                1, 1, 0, // max_idle_timeout
                3, 2, 0x43, 0xE8, // max_udp_payload_size: 1000
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
            ],
            // no extra auth
            |_| Ok(()),
        );
        assert_eq!(
            result.err(),
            Some(
                QuicError::new(
                    ErrorKind::TransportParameter,
                    FrameType::Crypto.into(),
                    "parameter 0x3: Invalid parameter value: out of bound 1200..=65527",
                )
                .into()
            )
        );
    }

    #[test]
    fn test_write_parameters() {
        let client_params = create_test_client_params();
        let params =
            ArcParameters::new_client(client_params, None, ConnectionId::from_slice(b"odcid"));
        let mut buf = Vec::new();
        params.load_local_params_into(&mut buf);

        assert!(!buf.is_empty());
    }

    #[tokio::test]
    async fn test_arc_parameters_error_handling() {
        let arc_params = ArcParameters::new_client(
            create_test_client_params(),
            None,
            ConnectionId::from_slice(b"odcid"),
        );

        // Simulate connection error
        let error = QuicError::new(
            ErrorKind::TransportParameter,
            FrameType::Crypto.into(),
            "test error",
        )
        .into();
        arc_params.on_conn_error(&error);

        assert!(
            arc_params
                .get_local_as::<bool>(ParameterId::GreaseQuicBit)
                .is_err()
        );
    }
}
