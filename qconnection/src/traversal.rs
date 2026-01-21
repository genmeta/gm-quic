use std::{io, net::SocketAddr};

use futures::{StreamExt, stream::FuturesUnordered};
use qbase::{
    frame::ReceiveFrame,
    net::{
        addr::RealAddr,
        route::{BleEndpontAddr, EndpointAddr, Link, Pathway, SocketEndpointAddr},
        tx::Signals,
    },
    packet::{ProductHeader, header::short::OneRttHeader},
};
use qevent::telemetry::Instrument;
use qinterface::{local::AddressEvent, logical::BindUri};
use qtraversal::{frame::TraversalFrame, nat::client::StunClientsComponent};
use tracing::Instrument as _;

use super::Components;
use crate::CidRegistry;

impl ReceiveFrame<(BindUri, Pathway, Link, TraversalFrame)> for Components {
    type Output = ();
    fn recv_frame(
        &self,
        frame: &(BindUri, Pathway, Link, TraversalFrame),
    ) -> Result<Self::Output, qbase::error::Error> {
        let Ok(pathway) = frame.1.try_into() else {
            return Ok(());
        };
        let Ok(link) = frame.2.try_into() else {
            return Ok(());
        };
        let bind_uri = frame.0.clone();
        let frame: TraversalFrame = frame.3.clone();

        self.puncher.recv_frame(&(bind_uri, pathway, link, frame))
    }
}

impl Components {
    pub fn subscribe_local_address(&self) {
        let location = &self.locations;
        let mut observer = location.subscribe();
        let conn = self.clone();

        let future = async move {
            let handle_address_event = |(bind_uri, event): (BindUri, AddressEvent)| {
                let event = match event.downcast::<RealAddr>() {
                    Ok(AddressEvent::Upsert(data)) => {
                        let real_addr = data.as_ref();
                        let endpoint_addr = match *real_addr {
                            RealAddr::Internet(addr) => {
                                EndpointAddr::Socket(SocketEndpointAddr::direct(addr))
                            }
                            RealAddr::Bluetooth(addr) => {
                                EndpointAddr::Ble(BleEndpontAddr::new(addr))
                            }
                            _ => return,
                        };
                        conn.add_local_endpoint(bind_uri, endpoint_addr);
                        return;
                    }
                    Ok(AddressEvent::Remove(_type_id)) => return,
                    Ok(AddressEvent::Closed) => return,
                    Err(event) => event,
                };
                let _event = match event.downcast::<SocketEndpointAddr>() {
                    Ok(AddressEvent::Upsert(data)) => {
                        let endpoint_addr = data.as_ref();
                        conn.add_local_endpoint(bind_uri.clone(), (*endpoint_addr).into());
                        if matches!(*endpoint_addr, SocketEndpointAddr::Agent { .. }) {
                            _ = conn
                                .add_local_punch_address(bind_uri.clone(), (*endpoint_addr).into());
                        }
                        return;
                    }
                    Ok(AddressEvent::Remove(_type_id)) => return,
                    Ok(AddressEvent::Closed) => return,
                    Err(_event) => return,
                };
            };

            loop {
                tokio::select! {
                    _ =  conn.conn_state.terminated() => break,
                    address_event = observer.recv() => {
                        match address_event {
                            Some(event) => handle_address_event(event),
                            None => break,
                        }
                    }
                }
            }
        };
        tokio::spawn(future.instrument_in_current().in_current_span());
    }

    // 添加本地直通地址 可以直接新建 path
    pub fn add_local_endpoint(&self, bind: BindUri, addr: EndpointAddr) {
        let addr = match addr {
            EndpointAddr::Socket(addr) => addr,
            _ => return,
        };
        tracing::debug!(target: "quic", bind_uri = %bind, %addr,"Add local endpoint");
        match self.puncher.add_local_endpoint(bind, addr) {
            Ok(ways) => {
                let ways: Vec<(BindUri, qtraversal::Link, qtraversal::PathWay)> = ways;
                ways.into_iter().for_each(|way| {
                    let _ = self.add_path(way.0, way.1.into(), way.2.into());
                });
            }
            Err(error) => {
                tracing::debug!(target: "quic", ?error, "Add local endpoint failed");
            }
        }
    }

    // 添加对端直通地址，可以直接新建 path
    pub fn add_peer_endpoint(&self, addr: EndpointAddr) {
        let addr = match addr {
            EndpointAddr::Socket(addr) => addr,
            _ => return,
        };
        tracing::debug!(target: "quic", %addr, "Add peer endpoint");
        match self.puncher.add_peer_endpoint(addr) {
            Ok(ways) => {
                let ways: Vec<(BindUri, qtraversal::Link, qtraversal::PathWay)> = ways;
                ways.into_iter().for_each(|way| {
                    let _ = self.add_path(way.0, way.1.into(), way.2.into());
                });
            }
            Err(error) => {
                tracing::debug!(target: "quic", ?error, "Add peer endpoint failed");
            }
        }
    }

    // 添加本地直连地址，用于打洞，不能直接新建路径
    pub fn add_local_punch_address(
        &self,
        bind_uri: BindUri,
        endpoint_addr: EndpointAddr,
    ) -> io::Result<()> {
        let iface = self
            .interfaces
            .borrow(&bind_uri)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))?;

        let local_addr = match endpoint_addr {
            EndpointAddr::Socket(socket_endpoint_addr) => socket_endpoint_addr.addr(),
            EndpointAddr::Ble(_) => return Err(std::io::ErrorKind::Unsupported.into()),
        };
        let conn = self.clone();

        let tasks = iface.with_component(|clinets: &StunClientsComponent| {
            clinets.with_clients(|map| {
                // workaround. clippy issue: https://github.com/rust-lang/rust-clippy/issues/16428
                #[allow(clippy::redundant_iter_cloned)]
                map.values()
                    .cloned()
                    .map(|client| async move { client.nat_type().await })
                    .collect::<FuturesUnordered<_>>()
            })
        })?;

        let Some(mut tasks) = tasks else {
            return Ok(());
        };

        tokio::spawn(async move {
            while let Some(result) = tasks.next().await {
                if let Ok(nat_type) = result {
                    _ = conn
                        .puncher
                        .add_local_address(bind_uri.clone(), local_addr, nat_type, 0);
                }
            }
        });
        Ok(())
    }

    pub fn remove_address(&self, addr: SocketAddr) {
        let _ = self.puncher.remove_local_address(addr);
    }
}

#[derive(Clone)]
pub struct PunchTransaction {
    cid_registry: CidRegistry,
}

impl PunchTransaction {
    pub(crate) fn new(cid_registry: CidRegistry) -> Self {
        Self { cid_registry }
    }
}

impl ProductHeader<OneRttHeader> for PunchTransaction {
    fn new_header(&self) -> Result<OneRttHeader, Signals> {
        Ok(OneRttHeader::new(
            false.into(),
            self.cid_registry
                .remote
                .latest_dcid()
                .ok_or(Signals::CONNECTION_ID)?,
        ))
    }
}
