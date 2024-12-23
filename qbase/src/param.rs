use std::{
    future::Future,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::BufMut;

use crate::{
    cid::ConnectionId,
    error::{Error, ErrorKind},
    frame::FrameType,
    sid::{Role, MAX_STREAMS_LIMIT},
};

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
#[derive(Debug, Default, Clone, Copy)]
struct Requirements {
    initial_source_connection_id: Option<ConnectionId>,
    retry_source_connection_id: Option<ConnectionId>,
    original_destination_connection_id: Option<ConnectionId>,
}

pub struct Pair {
    pub local: CommonParameters,
    pub remote: CommonParameters,
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
    role: Role,
    state: u8,
    client: ClientParameters,
    server: ServerParameters,
    remembered: Option<CommonParameters>,
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
    fn new_client(client: ClientParameters, remembered: Option<CommonParameters>) -> Self {
        Self {
            role: Role::Client,
            state: Self::CLIENT_READY,
            client,
            server: ServerParameters::default(),
            remembered,
            requirements: Requirements::default(),
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
            role: Role::Server,
            state: Self::SERVER_READY,
            client: ClientParameters::default(),
            server,
            remembered: None,
            requirements: Requirements::default(),
            wakers: Vec::with_capacity(2),
        }
    }

    fn local(&self) -> &CommonParameters {
        match self.role {
            Role::Client => self.client.deref(),
            Role::Server => self.server.deref(),
        }
    }

    fn remote(&self) -> Option<&CommonParameters> {
        if self.role == Role::Client && self.state & Self::SERVER_READY != 0 {
            Some(self.server.deref())
        } else if self.role == Role::Server && self.state & Self::CLIENT_READY != 0 {
            Some(self.client.deref())
        } else {
            None
        }
    }

    fn remembered(&self) -> Option<&CommonParameters> {
        self.remembered.as_ref()
    }

    fn set_initial_scid(&mut self, cid: ConnectionId) {
        if self.role == Role::Client {
            self.client.set_initial_source_connection_id(cid);
        } else {
            self.server.set_initial_source_connection_id(cid);
        }
    }

    fn set_retry_scid(&mut self, cid: ConnectionId) {
        assert_eq!(self.role, Role::Server);
        self.server.set_retry_source_connection_id(cid);
    }

    fn set_original_dcid(&mut self, cid: ConnectionId) {
        assert_eq!(self.role, Role::Server);
        self.server.set_original_destination_connection_id(cid);
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Option<Pair>> {
        if self.state == Self::CLIENT_READY | Self::SERVER_READY {
            Poll::Ready(Some(Pair {
                local: *self.local(),
                remote: *self.remote().unwrap(),
            }))
        } else {
            self.wakers.push(cx.waker().clone());
            Poll::Pending
        }
    }

    fn has_rcvd_remote_params(&self) -> bool {
        self.state == Self::CLIENT_READY | Self::SERVER_READY
    }

    fn recv_remote_params(&mut self, params: &[u8]) -> Result<(), Error> {
        self.state = Self::CLIENT_READY | Self::SERVER_READY;
        self.parse_remote_params(params).map_err(|ne| {
            Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                ne.to_string(),
            )
        })?;
        self.state = Self::CLIENT_READY | Self::SERVER_READY;
        self.validate_remote_params()?;
        self.authenticate_cids()?;

        self.wake_all();
        Ok(())
    }

    fn wake_all(&mut self) {
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }

    fn parse_remote_params<'b>(&mut self, input: &'b [u8]) -> nom::IResult<&'b [u8], ()> {
        if self.role == Role::Client {
            be_server_parameters(input, &mut self.server)
        } else {
            be_client_parameters(input, &mut self.client)
        }
    }

    fn initial_scid_from_peer_need_equal(&mut self, cid: ConnectionId) {
        // TODO: 暂时这样实现
        if self.requirements.initial_source_connection_id.is_none() {
            self.requirements.initial_source_connection_id = Some(cid)
        }
    }

    fn retry_scid_from_server_need_equal(&mut self, cid: ConnectionId) {
        assert_eq!(self.role, Role::Client);
        self.requirements.retry_source_connection_id = Some(cid)
    }

    fn original_dcid_from_server_need_equal(&mut self, cid: ConnectionId) {
        assert_eq!(self.role, Role::Client);
        self.requirements.original_destination_connection_id = Some(cid)
    }

    fn authenticate_cids(&self) -> Result<(), Error> {
        fn param_error(reason: &'static str) -> Error {
            Error::new(ErrorKind::TransportParameter, FrameType::Crypto, reason)
        }

        match self.role {
            Role::Client => {
                if self.server.initial_source_connection_id
                    != self
                        .requirements
                        .initial_source_connection_id
                        .expect("The initial_source_connection_id transport parameter MUST be present in the Initial packet from the server")
                {
                    return Err(param_error("Initial Source Connection ID from server mismatch"));
                }
                if self.server.retry_source_connection_id
                    != self.requirements.retry_source_connection_id
                {
                    return Err(param_error("Retry Source Connection ID mismatch"));
                }
                if self.server.original_destination_connection_id != self.requirements
                        .original_destination_connection_id
                        .expect("The original_destination_connection_id transport parameter MUST be present in the Initial packet from the server")
                {
                    return Err(param_error("Original Destination Connection ID mismatch"));
                }
            }
            Role::Server => {
                if self.client.initial_source_connection_id
                    != self
                        .requirements
                        .initial_source_connection_id
                        .expect("The initial_source_connection_id transport parameter MUST be present in the Initial packet from the client")
                {
                    return Err(param_error("Initial Source Connection ID from client mismatch"));
                }
            }
        }

        Ok(())
    }

    fn validate_remote_params(&self) -> Result<(), Error> {
        let remote_params = self.remote().unwrap();
        let reason = if remote_params.max_udp_payload_size.into_inner() < 1200 {
            Some("max_udp_payload_size from peer must be at least 1200")
        } else if remote_params.ack_delay_exponent.into_inner() > 20 {
            Some("ack_delay_exponent from peer must be at most 20")
        } else if remote_params.max_ack_delay.into_inner() > 1 << 14 {
            Some("max_ack_delay from peer must be at most 2^14")
        } else if remote_params.active_connection_id_limit.into_inner() < 2 {
            Some("active_connection_id_limit from peer must be at least 2")
        } else if remote_params.initial_max_streams_bidi.into_inner() > MAX_STREAMS_LIMIT {
            Some("initial_max_streams_bidi from peer must be at most 2^60 - 1")
        } else if remote_params.initial_max_streams_uni.into_inner() > MAX_STREAMS_LIMIT {
            Some("initial_max_streams_uni from peer must be at most 2^60 - 1")
        } else {
            None
        };
        match reason {
            Some(reason) => Err(Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                reason,
            )),
            None => Ok(()),
        }
    }
}

/// A [`bytes::BufMut`] extension trait for writing transport parameters.
pub trait WriteParameters: WriteServerParameters {
    /// Writes the local transport parameters to the buffer.
    ///
    /// - For the client, the transport parameters sent to the peer
    ///   must be client transport parameters;
    /// - For the server, the transport parameters sent to the peer
    ///   must be server transport parameters.
    fn put_parameters(&mut self, parameters: &Parameters);
}

impl<T: BufMut> WriteParameters for T {
    fn put_parameters(&mut self, parameters: &Parameters) {
        if parameters.role == Role::Client {
            self.put_client_parameters(&parameters.client);
        } else {
            self.put_server_parameters(&parameters.server);
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
    pub fn new_client(client: ClientParameters, remembered: Option<CommonParameters>) -> Self {
        Self(Arc::new(Mutex::new(Ok(Parameters::new_client(
            client, remembered,
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

    /// Returns the local transport parameters.
    /// Returns None if some connection error occurred.
    ///
    /// - For the client, the local transport parameters are client
    ///   transport parameters;
    /// - For the server, the local transport parameters are server
    ///   transport parameters.
    pub fn local(&self) -> Option<CommonParameters> {
        let guard = self.0.lock().unwrap();
        match guard.deref() {
            Ok(params) => Some(*params.local()),
            Err(_) => None,
        }
    }

    /// Returns the remote transport parameters.
    /// Returns None if the remote transport parameters have not
    /// been received or some connection error occurred.
    ///
    /// - For the client, the local transport parameters are server
    ///   transport parameters;
    /// - For the server, the local transport parameters are client
    ///   transport parameters.
    pub fn remote(&self) -> Option<CommonParameters> {
        let guard = self.0.lock().unwrap();
        match guard.deref() {
            Ok(params) => params.remote().cloned(),
            Err(_) => None,
        }
    }

    /// Returns the remembered server transport parameters if exist,
    /// which means the client connected the server, and stored the
    /// server transport parameters.
    ///
    /// It is meaningful only for the client, to send early data
    /// with 0Rtt packets before receving the server transport params.
    pub fn remembered(&self) -> Option<CommonParameters> {
        let guard = self.0.lock().unwrap();
        match guard.deref() {
            Ok(params) => params.remembered().cloned(),
            Err(_) => None,
        }
    }

    /// Sets the initial source connection ID in local transport parameters.
    pub fn set_initial_scid(&self, cid: ConnectionId) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.set_initial_scid(cid);
        }
    }

    /// Sets the retry source connection ID in the server
    /// transport parameters.
    ///
    /// It is meaningful only for the client, because only
    /// server can send the Retry packet.
    pub fn set_retry_scid(&self, cid: ConnectionId) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.set_retry_scid(cid);
        }
    }

    /// Sets the original destination connection ID in the server
    /// transport parameters.
    ///
    /// It is meaningful only for the server, because only server
    /// need extract the original destination connection ID from
    /// the first packet sent by the client, and echo it back to
    /// the client.
    pub fn set_original_dcid(&self, cid: ConnectionId) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.set_original_dcid(cid);
        }
    }

    /// Load the local transport parameters into the buffer, which
    /// will be send to the peer soon.
    pub fn load_local_params_into(&self, buf: &mut Vec<u8>) {
        let guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref() {
            buf.put_parameters(params);
        }
    }

    /// No matter the client or server, after receiving the Initial
    /// packet from the peer, the initial_source_connection_id in
    /// the remote transport parameters must equal the source connection
    /// id in the received Initial packet.
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

    /// After receiving the Initial packet from the server, the
    /// original_destination_connection_id in the server transport
    /// parameters must equal the destination connection id in the
    /// first packet sent by the client.
    pub fn original_dcid_from_server_need_equal(&self, cid: ConnectionId) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.original_dcid_from_server_need_equal(cid);
        }
    }

    /// Being called when the remote transport parameters are received.
    /// It will parse and check the remote transport parameters,
    /// and wake all the wakers waiting for the remote transport parameters
    /// if the remote transport parameters are valid.
    pub fn recv_remote_params(&self, bytes: &[u8]) -> Result<(), Error> {
        let mut guard = self.0.lock().unwrap();
        let params = guard.as_mut().map_err(|e| e.clone())?;
        // 避免外界拿到错误的参数
        if let Err(e) = params.recv_remote_params(bytes) {
            params.wake_all();
            *guard = Err(e.clone());
            return Err(e);
        }
        Ok(())
    }

    /// Returns true if the remote transport parameters have been received.
    ///
    /// It is usually used to avoid processing remote transport parameters
    /// more than once.
    pub fn has_rcvd_remote_params(&self) -> bool {
        let guard = self.0.lock().unwrap();
        match guard.deref() {
            Ok(params) => params.has_rcvd_remote_params(),
            Err(_) => false,
        }
    }

    /// When some connection error occurred, convert this parameters
    /// into error state.
    pub fn on_conn_error(&self, error: &Error) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.wake_all();
            *guard = Err(error.clone());
        }
    }
}

impl Future for ArcParameters {
    type Output = Option<Pair>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            Err(_) => Poll::Ready(None),
            Ok(params) => params.poll_ready(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let params = Parameters::new_client(client_params, None);
        assert_eq!(params.role, Role::Client);
        assert_eq!(params.state, Parameters::CLIENT_READY);

        let server_params = create_test_server_params();
        let params = Parameters::new_server(server_params);
        assert_eq!(params.role, Role::Server);
        assert_eq!(params.state, Parameters::SERVER_READY);
    }

    #[test]
    fn test_authenticate_cids() {
        let client_params = create_test_client_params();
        let mut params = Parameters::new_client(client_params, None);

        let server_cid = ConnectionId::from_slice(b"server_test");
        params.initial_scid_from_peer_need_equal(server_cid);

        let original_cid = ConnectionId::from_slice(b"original");
        params.original_dcid_from_server_need_equal(original_cid);

        // Setup server parameters to match requirements
        params.server.set_initial_source_connection_id(server_cid);
        params
            .server
            .set_original_destination_connection_id(original_cid);

        assert!(params.authenticate_cids().is_ok());
    }

    #[test]
    fn test_parameters_as_client() {
        let client_params = create_test_client_params();
        let arc_params = ArcParameters::new_client(client_params, None);

        // Test local params
        let local = arc_params.local().unwrap();
        assert!(local.max_udp_payload_size.into_inner() >= 1200);

        // Test remote params before receiving
        assert!(arc_params.remote().is_none());

        // Test remembered params
        assert!(arc_params.remembered().is_none());

        // Test loading local params
        let mut buf = Vec::new();
        arc_params.load_local_params_into(&mut buf);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_validate_remote_params() {
        // Test invalid max_udp_payload_size
        let mut params = Parameters::new_server(create_test_server_params());
        let result = params.recv_remote_params(&[
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
        ]);
        assert_eq!(
            result,
            Err(Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                "max_udp_payload_size from peer must be at least 1200",
            ))
        );
    }

    #[test]
    fn test_write_parameters() {
        let client_params = create_test_client_params();
        let params = Parameters::new_client(client_params, None);
        let mut buf = Vec::new();
        buf.put_parameters(&params);
        assert!(!buf.is_empty());
    }

    #[tokio::test]
    async fn test_arc_parameters_error_handling() {
        let arc_params = ArcParameters::new_client(create_test_client_params(), None);

        // Simulate connection error
        let error = Error::new(
            ErrorKind::TransportParameter,
            FrameType::Crypto,
            "test error",
        );
        arc_params.on_conn_error(&error);

        assert!(arc_params.local().is_none());
        assert!(arc_params.remote().is_none());
    }
}
