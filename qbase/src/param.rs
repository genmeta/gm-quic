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

#[derive(Debug, Default, Clone, Copy)]
struct Requirements {
    initial_source_connection_id: ConnectionId,
    retry_source_connection_id: Option<ConnectionId>,
    original_destination_connection_id: Option<ConnectionId>,
}

pub struct Pair {
    pub local: CommonParameters,
    pub remote: CommonParameters,
}

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

    fn new_client(client: ClientParameters, remembered: Option<CommonParameters>) -> Self {
        Self {
            role: Role::Client,
            state: Self::CLIENT_READY,
            client,
            server: ServerParameters::default(),
            remembered,
            requirements: Requirements {
                initial_source_connection_id: ConnectionId::default(),
                retry_source_connection_id: None,
                original_destination_connection_id: None,
            },
            wakers: Vec::with_capacity(2),
        }
    }

    fn new_server(server: ServerParameters) -> Self {
        Self {
            role: Role::Server,
            state: Self::SERVER_READY,
            client: ClientParameters::default(),
            server,
            remembered: None,
            requirements: Requirements {
                initial_source_connection_id: ConnectionId::default(),
                retry_source_connection_id: None,
                original_destination_connection_id: None,
            },
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
        match self.role {
            Role::Client => {
                if self.state & Self::SERVER_READY != 0 {
                    Some(self.server.deref())
                } else {
                    None
                }
            }
            Role::Server => {
                if self.state & Self::CLIENT_READY != 0 {
                    Some(self.client.deref())
                } else {
                    None
                }
            }
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
        self.server.set_retry_source_connection_id(Some(cid));
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
        self.parse_remote_params(params).map_err(|ne| {
            Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                ne.to_string(),
            )
        })?;
        self.validate_remote_params()?;
        self.authenticate_cids()?;

        self.state = Self::CLIENT_READY | Self::SERVER_READY;
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
        self.requirements.initial_source_connection_id = cid
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
        if self.role == Role::Client {
            if self.server.initial_source_connection_id
                != self.requirements.initial_source_connection_id
            {
                return Err(Error::new(
                    ErrorKind::TransportParameter,
                    FrameType::Crypto,
                    "Initial Source Connection ID mismatch",
                ));
            }

            if self.server.retry_source_connection_id
                != self.requirements.retry_source_connection_id
            {
                return Err(Error::new(
                    ErrorKind::TransportParameter,
                    FrameType::Crypto,
                    "Retry Source Connection ID mismatch",
                ));
            }

            if self.server.original_destination_connection_id
                != self
                    .requirements
                    .original_destination_connection_id
                    .expect("The original_destination_connection_id transport parameter MUST be present in the Initial packet from the server")
            {
                return Err(Error::new(
                    ErrorKind::TransportParameter,
                    FrameType::Crypto,
                    "Original Destination Connection ID mismatch",
                ));
            }
        } else if self.client.initial_source_connection_id
            != self.requirements.initial_source_connection_id
        {
            return Err(Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                "Initial Source Connection ID mismatch",
            ));
        }

        Ok(())
    }

    fn validate_remote_params(&self) -> Result<(), Error> {
        let remote_params = self.remote().unwrap();
        if remote_params.max_udp_payload_size.into_inner() < 1200 {
            return Err(Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                "ack_delay_exponent must be at most 20",
            ));
        }
        if remote_params.ack_delay_exponent.into_inner() > 20 {
            return Err(Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                "ack_delay_exponent must be at most 20",
            ));
        }
        if remote_params.max_ack_delay.into_inner() > 1 << 14 {
            return Err(Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                "max_ack_delay must be at most 2^14",
            ));
        }
        if remote_params.active_connection_id_limit.into_inner() < 2 {
            return Err(Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                "active_connection_id_limit must be at least 2",
            ));
        }
        if remote_params.initial_max_streams_bidi.into_inner() > MAX_STREAMS_LIMIT {
            return Err(Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                "active_connection_id_limit must be at least 2",
            ));
        }
        if remote_params.initial_max_streams_uni.into_inner() > MAX_STREAMS_LIMIT {
            return Err(Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                "active_connection_id_limit must be at least 2",
            ));
        }

        Ok(())
    }
}

pub trait WriteParameters: WriteServerParameters {
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

#[derive(Debug, Clone)]
pub struct ArcParameters(Arc<Mutex<Result<Parameters, Error>>>);

impl ArcParameters {
    pub fn new_client(client: ClientParameters, remembered: Option<CommonParameters>) -> Self {
        Self(Arc::new(Mutex::new(Ok(Parameters::new_client(
            client, remembered,
        )))))
    }

    pub fn new_server(server: ServerParameters) -> Self {
        Self(Arc::new(Mutex::new(Ok(Parameters::new_server(server)))))
    }

    pub fn local(&self) -> Option<CommonParameters> {
        let guard = self.0.lock().unwrap();
        match guard.deref() {
            Ok(params) => Some(*params.local()),
            Err(_) => None,
        }
    }

    pub fn remote(&self) -> Option<CommonParameters> {
        let guard = self.0.lock().unwrap();
        match guard.deref() {
            Ok(params) => params.remote().cloned(),
            Err(_) => None,
        }
    }

    pub fn remembered(&self) -> Option<CommonParameters> {
        let guard = self.0.lock().unwrap();
        match guard.deref() {
            Ok(params) => params.remembered().cloned(),
            Err(_) => None,
        }
    }

    pub fn set_initial_scid(&self, cid: ConnectionId) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.set_initial_scid(cid);
        }
    }

    pub fn set_retry_scid(&self, cid: ConnectionId) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.set_retry_scid(cid);
        }
    }

    pub fn set_original_dcid(&self, cid: ConnectionId) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.set_original_dcid(cid);
        }
    }

    pub fn load_local_params_into(&self, buf: &mut Vec<u8>) {
        let guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref() {
            buf.put_parameters(params);
        }
    }

    pub fn initial_scid_from_peer_need_equal(&self, cid: ConnectionId) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.initial_scid_from_peer_need_equal(cid);
        }
    }

    pub fn retry_scid_from_server_need_equal(&self, cid: ConnectionId) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.retry_scid_from_server_need_equal(cid);
        }
    }

    pub fn original_dcid_from_server_need_equal(&self, cid: ConnectionId) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(params) = guard.deref_mut() {
            params.original_dcid_from_server_need_equal(cid);
        }
    }

    pub fn recv_remote_params(&self, bytes: &[u8]) -> Result<(), Error> {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            Err(e) => Err(e.clone()),
            Ok(params) => params.recv_remote_params(bytes),
        }
    }

    pub fn has_rcvd_remote_params(&self) -> bool {
        let guard = self.0.lock().unwrap();
        match guard.deref() {
            Ok(params) => params.has_rcvd_remote_params(),
            Err(_) => false,
        }
    }

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
mod test {
    use super::ClientParameters;

    #[test]
    fn test_common_parameters() {
        let mut client_params = ClientParameters::default();
        client_params.set_ack_delay_exponent(0x12);

        println!("{:?}", client_params);
    }
}
