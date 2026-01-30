use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    net::SocketAddr,
    ops::Deref,
};

use futures::io;
use qbase::net::addr::SocketEndpointAddr;
use qinterface::bind_uri::BindUri;

use crate::{
    frame::{add_address::AddAddressFrame, remove_address::RemoveAddressFrame},
    nat::client::NatType,
};

#[derive(Default)]
pub struct AddressBook {
    local: HashMap<u32, (BindUri, AddAddressFrame)>,
    remote: HashMap<u32, AddAddressFrame>,
    local_endpoint: HashSet<(BindUri, SocketEndpointAddr)>,
    remote_endpoint: HashSet<SocketEndpointAddr>,
    largest_seq_num: u32,
}

impl AddressBook {
    pub(crate) fn add_local_address(
        &mut self,
        bind: BindUri,
        addr: SocketAddr,
        tire: u32,
        nat_type: NatType,
    ) -> io::Result<AddAddressFrame> {
        if self
            .local
            .values()
            .any(|(_local, frame)| *frame.deref() == addr)
        {
            tracing::debug!(target: "quic", %addr, "Duplicate local address");
            return Err(io::Error::other("Duplicate local address"));
        }
        let frame = AddAddressFrame::new(self.largest_seq_num, addr, tire, nat_type as u32);
        self.local.insert(self.largest_seq_num, (bind, frame));
        self.largest_seq_num += 1;
        Ok(frame)
    }

    pub(crate) fn add_local_endpoint(
        &mut self,
        bind: BindUri,
        addr: SocketEndpointAddr,
    ) -> io::Result<()> {
        if !self.local_endpoint.insert((bind, addr)) {
            return Err(io::Error::other("Duplicate local endpoint"));
        }
        Ok(())
    }

    pub(crate) fn add_peer_endpoint(&mut self, endpoint: SocketEndpointAddr) -> io::Result<()> {
        if !self.remote_endpoint.insert(endpoint) {
            return Err(io::Error::other("Duplicate remote endpoint"));
        }
        Ok(())
    }

    pub(crate) fn remote_endpoint(&self) -> &HashSet<SocketEndpointAddr> {
        &self.remote_endpoint
    }

    pub(crate) fn local_endpoint(&self) -> &HashSet<(BindUri, SocketEndpointAddr)> {
        &self.local_endpoint
    }

    pub(crate) fn remove_local_address(
        &mut self,
        addr: SocketAddr,
    ) -> io::Result<RemoveAddressFrame> {
        let Some(seq_num) = self
            .local
            .iter()
            .find(|(_, (_local, frame))| *frame.deref() == addr)
            .map(|(key, _)| *key)
        else {
            tracing::debug!(target: "quic", %addr, "No matching local address to remove");
            return Err(io::Error::other("No matching local address"));
        };
        self.local.remove(&seq_num).map(|(_local, _frame)| seq_num);
        Ok(RemoveAddressFrame {
            seq_num: seq_num.into(),
        })
    }

    pub(crate) fn get_local_address(&self, seq_num: &u32) -> Option<(BindUri, AddAddressFrame)> {
        self.local.get(seq_num).cloned()
    }

    pub(crate) fn add_remote_address(&mut self, remote: AddAddressFrame) -> io::Result<()> {
        match self.remote.entry(remote.seq_num()) {
            Entry::Occupied(_) => {
                tracing::debug!(target: "quic", remote_seq_num = remote.seq_num(), "Duplicate remote address");
                return Err(io::Error::other("Duplicate remote address"));
            }
            Entry::Vacant(entry) => {
                entry.insert(remote);
            }
        }
        Ok(())
    }

    pub(crate) fn remove_remote_address(&mut self, seq_num: u32) -> Option<AddAddressFrame> {
        self.remote.remove(&seq_num)
    }

    pub(crate) fn pick_local_address(
        &self,
        remote: &AddAddressFrame,
    ) -> io::Result<(BindUri, AddAddressFrame)> {
        let mut addrs: Vec<_> = self
            .local
            .iter()
            .filter(|(_seq, (_local, frame))| {
                frame.tire() == remote.tire() && frame.is_ipv4() == remote.is_ipv4()
            })
            .map(|(_, addr)| addr.clone())
            .collect();

        if addrs.is_empty() {
            tracing::debug!(target: "quic", ?remote, "No matching local address for remote address");
            return Err(io::Error::other("No matching local address"));
        }

        const NAT_PRIORITY: [NatType; 5] = [
            NatType::FullCone,
            NatType::RestrictedCone,
            NatType::RestrictedPort,
            NatType::Dynamic,
            NatType::Symmetric,
        ];

        addrs.sort_by_key(|(_addr, frame)| {
            NAT_PRIORITY
                .iter()
                .position(|&x| x == frame.nat_type())
                .unwrap_or(usize::MAX)
        });

        let (bind, frame) = addrs
            .iter()
            .find(|(_, frame)| *frame != *remote)
            .ok_or_else(|| io::Error::other("No matching local address"))?;

        Ok((bind.clone(), *frame))
    }
}
