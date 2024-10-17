use std::sync::Arc;

use qbase::{
    cid::ConnectionId,
    config::Parameters,
    packet::{
        header::{
            long::{self, InitialHeader, RetryHeader},
            GetDcid, GetScid,
        },
        DataHeader, DataPacket,
    },
    token::{ArcTokenRegistry, TokenProvider},
};
use qconnection::{connection::ArcConnection, path::Pathway, router::Router};
use qudp::ArcUsc;

use super::RawQuicServer;
use crate::{ConnKey, QuicConnection, CONNECTIONS};

pub struct Incoming<'s> {
    /// The incoming packet, it must be a Initial or Retry packet.
    pub packet: DataPacket,
    /// The pathway of the incoming packet.
    pub way: Pathway,
    pub usc: ArcUsc,

    server: &'s RawQuicServer,
}

impl Incoming<'_> {
    pub(super) fn new(
        packet: DataPacket,
        way: Pathway,
        usc: ArcUsc,
        server: &RawQuicServer,
    ) -> Incoming<'_> {
        Incoming {
            packet,
            way,
            usc,
            server,
        }
    }
}

fn initial_server_keys(tls: &rustls::ServerConfig, dcid: ConnectionId) -> rustls::quic::Keys {
    let suite = tls
        .crypto_provider()
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => suite.quic_suite(),
            _ => None,
        })
        .unwrap();
    suite.keys(&dcid, rustls::Side::Server, rustls::quic::Version::V1)
}

impl Incoming<'_> {
    #[inline]
    pub fn accpet(self) -> QuicConnection {
        self.accpet_with(None, None, None)
    }

    pub fn ignore(self) {}

    // TODO
    pub fn retry(self, header: impl FnOnce(InitialHeader) -> RetryHeader) -> ! {
        _ = (self, header);
        unimplemented!()
    }

    pub fn accpet_with(
        self,
        parameters: impl Into<Option<Parameters>>,
        tls_config: impl Into<Option<Arc<rustls::ServerConfig>>>,
        token_provider: impl Into<Option<Arc<dyn TokenProvider>>>,
    ) -> QuicConnection {
        let (initial_dcid, client_initial_dcid) = match &self.packet.header {
            DataHeader::Long(hdr @ long::DataHeader::Initial(_))
            | DataHeader::Long(hdr @ long::DataHeader::ZeroRtt(_)) => {
                (*hdr.get_scid(), *hdr.get_dcid())
            }
            _ => unreachable!(),
        };

        let parameters = parameters.into().unwrap_or_else(Parameters::default); // TODO: select by SN

        let fallback_tls_config = || self.server.tls_config.clone();
        let tls_config = tls_config.into().unwrap_or_else(fallback_tls_config);

        let fallback_token_provider = || self.server.token_provider.clone();
        let token_provider = token_provider.into().or_else(fallback_token_provider);

        let initial_scid =
            std::iter::repeat_with(|| ConnectionId::random_gen_with_mark(8, 0, 0x7F))
                .find(|cid| !CONNECTIONS.contains_key(&ConnKey::Server(*cid)))
                .unwrap();
        let initial_keys = initial_server_keys(&tls_config, client_initial_dcid);
        let token_registry = token_provider
            .map(ArcTokenRegistry::with_provider)
            .unwrap_or_else(ArcTokenRegistry::default_provider);

        let arc_conn = ArcConnection::new_server(
            initial_scid,
            initial_dcid,
            parameters,
            initial_keys,
            tls_config,
            token_registry,
        );

        _ = Router::try_to_route_packet_from(self.packet, self.way, &self.usc);

        let conn_key = ConnKey::Server(initial_scid);
        let conn = QuicConnection {
            key: conn_key,
            inner: arc_conn,
        };
        CONNECTIONS.insert(conn_key, conn.clone());

        conn
    }
}
