use std::{io, net::SocketAddr};

use qinterface::io::RefIO;
use tokio::task::JoinHandle;
use tracing::{debug, info};

use super::{
    msg::{Attr, Request, Response},
    router::StunRouter,
};
use crate::nat::{
    iface::StunIO,
    msg::{CHANGE_IP, CHANGE_PORT, Packet},
};

pub struct StunServer<I> {
    ifaces: [(I, StunRouter); 2],
    change: SocketAddr,
}

impl<I: RefIO + 'static> StunServer<I> {
    pub fn new(ifaces: [(I, StunRouter); 2], change: SocketAddr) -> Self {
        info!(
            "new stun io0 {:?}, io1 {:?}",
            ifaces[0].0.iface().local_addr(),
            ifaces[1].0.iface().local_addr()
        );

        Self { ifaces, change }
    }

    pub async fn run(&mut self) -> io::Result<()> {
        info!("Server started");
        let tasks = [
            self.spawn_recv_request_task(self.ifaces[0].0.clone(), self.ifaces[0].1.clone())?,
            self.spawn_recv_request_task(self.ifaces[1].0.clone(), self.ifaces[1].1.clone())?,
        ];

        let results = futures::future::join_all(tasks).await;
        for result in results {
            result??;
        }
        info!("Server finished");
        Ok(())
    }

    fn change_port(&self, io: &(impl StunIO + ?Sized)) -> io::Result<SocketAddr> {
        if io.local_addr()? == self.ifaces[0].0.iface().local_addr()? {
            self.ifaces[1].0.iface().local_addr()
        } else {
            self.ifaces[0].0.iface().local_addr()
        }
    }

    fn spawn_recv_request_task(
        &self,
        ref_iface: I,
        stun_router: StunRouter,
    ) -> io::Result<JoinHandle<io::Result<()>>> {
        let local_addr = ref_iface.iface().local_addr()?;
        let change_port_addr = self.change_port(ref_iface.iface())?;
        let change_ip_and_port_addr = SocketAddr::new(self.change.ip(), change_port_addr.port());
        Ok(tokio::spawn(async move {
            while let Some((request, txid, src)) = stun_router.receive_request().await {
                debug!(target: "stun", ?request, "recv request");
                match (request.change_request(), request.response_address()) {
                    (Some(changes), _) => {
                        let mut addr = src;
                        if changes & CHANGE_IP != 0 && changes & CHANGE_PORT != 0 {
                            addr = change_ip_and_port_addr;
                        } else if changes & CHANGE_PORT != 0 {
                            addr = change_port_addr;
                        }
                        let request = Request::with_response_addr(src);
                        debug!(target: "stun", ?request, to = %addr, "send request");
                        ref_iface
                            .iface()
                            .send_stun_packet(Packet::Request(request), txid, addr)
                            .await?;
                    }
                    (None, Some(&response_addr)) => {
                        let response = Response::with(vec![
                            Attr::SourceAddress(local_addr),
                            Attr::MappedAddress(response_addr),
                            Attr::ChangedAddress(change_ip_and_port_addr),
                        ]);
                        debug!(target: "stun", ?response, to = %response_addr, "send response");
                        ref_iface
                            .iface()
                            .send_stun_packet(Packet::Response(response), txid, response_addr)
                            .await?;
                    }
                    _ => {
                        let response = Response::with(vec![
                            Attr::SourceAddress(local_addr),
                            Attr::MappedAddress(src),
                            Attr::ChangedAddress(change_ip_and_port_addr),
                        ]);
                        debug!(target: "stun", ?response, to = %src, "send response");
                        ref_iface
                            .iface()
                            .send_stun_packet(Packet::Response(response), txid, src)
                            .await?;
                    }
                }
            }
            debug!(target: "stun", "Request handler finished - no more requests");
            Ok(())
        }))
    }
}
