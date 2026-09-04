use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use qbase::net::addr::{EndpointAddr, Kind};
use thiserror::Error;
use tokio::sync::watch;

#[derive(Debug, Error)]
pub enum AddressBookError {
    #[error("{0} is already present in the address book")]
    Duplicate(EndpointAddr),
    #[error("expected a Direct endpoint")]
    ExpectedDirect,
    #[error("expected an Agent endpoint")]
    ExpectedMediate,
    #[error("a bound address can publish at most three Agent endpoints")]
    TooManyAgents,
}

#[derive(Default)]
struct Addresses {
    inner: HashMap<EndpointAddr, SocketAddr>,
    outer: HashMap<EndpointAddr, SocketAddr>,
    agents: HashMap<EndpointAddr, SocketAddr>,
}

pub struct AddressBook {
    addresses: RwLock<Addresses>,
    ddns: watch::Sender<Arc<[EndpointAddr]>>,
    mdns: RwLock<HashMap<SocketAddr, watch::Sender<Arc<[EndpointAddr]>>>>,
}

impl Default for AddressBook {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressBook {
    pub fn new() -> Self {
        let (ddns, _) = watch::channel(Arc::from([]));
        Self {
            addresses: RwLock::new(Addresses::default()),
            ddns,
            mdns: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert_inner(
        &self,
        bound: SocketAddr,
        endpoint: EndpointAddr,
    ) -> Result<(), AddressBookError> {
        ensure_direct(endpoint)?;
        self.insert(bound, endpoint, |addresses| &mut addresses.inner)?;
        self.publish_mdns(bound);
        Ok(())
    }

    pub fn insert_outer(
        &self,
        bound: SocketAddr,
        endpoint: EndpointAddr,
    ) -> Result<(), AddressBookError> {
        ensure_direct(endpoint)?;
        self.insert(bound, endpoint, |addresses| &mut addresses.outer)?;
        self.publish_ddns();
        Ok(())
    }

    pub fn insert_agent(
        &self,
        bound: SocketAddr,
        endpoint: EndpointAddr,
    ) -> Result<(), AddressBookError> {
        if endpoint.kind() != Kind::Mediate {
            return Err(AddressBookError::ExpectedMediate);
        }

        let mut addresses = self.addresses.write().unwrap();
        self.ensure_absent(&addresses, endpoint)?;
        let agent_count = addresses
            .agents
            .values()
            .filter(|candidate| **candidate == bound)
            .count();
        if agent_count >= 3 {
            return Err(AddressBookError::TooManyAgents);
        }
        addresses.agents.insert(endpoint, bound);
        drop(addresses);
        self.publish_ddns();
        Ok(())
    }

    pub fn remove_bound(&self, bound: SocketAddr) {
        let mut addresses = self.addresses.write().unwrap();
        addresses.inner.retain(|_, candidate| *candidate != bound);
        addresses.outer.retain(|_, candidate| *candidate != bound);
        addresses.agents.retain(|_, candidate| *candidate != bound);
        drop(addresses);
        self.publish_ddns();
        self.publish_all_mdns();
    }

    pub fn subscribe_ddns(&self) -> watch::Receiver<Arc<[EndpointAddr]>> {
        self.ddns.subscribe()
    }

    pub fn subscribe_mdns(&self, bound: SocketAddr) -> watch::Receiver<Arc<[EndpointAddr]>> {
        if let Some(sender) = self.mdns.read().unwrap().get(&bound) {
            return sender.subscribe();
        }

        let snapshot = self.mdns_snapshot(bound);
        let mut publishers = self.mdns.write().unwrap();
        publishers
            .entry(bound)
            .or_insert_with(|| watch::channel(snapshot).0)
            .subscribe()
    }

    pub fn ddns_endpoints(&self) -> Arc<[EndpointAddr]> {
        self.ddns_snapshot()
    }

    pub fn mdns_endpoints(&self, bound: SocketAddr) -> Arc<[EndpointAddr]> {
        self.mdns_snapshot(bound)
    }

    fn insert(
        &self,
        bound: SocketAddr,
        endpoint: EndpointAddr,
        select: impl FnOnce(&mut Addresses) -> &mut HashMap<EndpointAddr, SocketAddr>,
    ) -> Result<(), AddressBookError> {
        let mut addresses = self.addresses.write().unwrap();
        self.ensure_absent(&addresses, endpoint)?;
        select(&mut addresses).insert(endpoint, bound);
        Ok(())
    }

    fn ensure_absent(
        &self,
        addresses: &Addresses,
        endpoint: EndpointAddr,
    ) -> Result<(), AddressBookError> {
        if addresses.inner.contains_key(&endpoint)
            || addresses.outer.contains_key(&endpoint)
            || addresses.agents.contains_key(&endpoint)
        {
            return Err(AddressBookError::Duplicate(endpoint));
        }
        Ok(())
    }

    fn publish_ddns(&self) {
        self.ddns.send_replace(self.ddns_snapshot());
    }

    fn publish_mdns(&self, bound: SocketAddr) {
        let snapshot = self.mdns_snapshot(bound);
        if let Some(sender) = self.mdns.read().unwrap().get(&bound) {
            sender.send_replace(snapshot);
        }
    }

    fn publish_all_mdns(&self) {
        let bounds = self
            .mdns
            .read()
            .unwrap()
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for bound in bounds {
            self.publish_mdns(bound);
        }
    }

    fn ddns_snapshot(&self) -> Arc<[EndpointAddr]> {
        let addresses = self.addresses.read().unwrap();
        let mut endpoints = addresses
            .outer
            .keys()
            .chain(addresses.agents.keys())
            .copied()
            .collect::<Vec<_>>();
        endpoints.sort_unstable();
        endpoints.into()
    }

    fn mdns_snapshot(&self, bound: SocketAddr) -> Arc<[EndpointAddr]> {
        let addresses = self.addresses.read().unwrap();
        let mut endpoints = addresses
            .inner
            .iter()
            .filter_map(|(endpoint, candidate)| (*candidate == bound).then_some(*endpoint))
            .collect::<Vec<_>>();
        endpoints.sort_unstable();
        endpoints.into()
    }
}

fn ensure_direct(endpoint: EndpointAddr) -> Result<(), AddressBookError> {
    if matches!(endpoint, EndpointAddr::Direct { .. }) {
        Ok(())
    } else {
        Err(AddressBookError::ExpectedDirect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishes_inner_to_mdns_and_outer_agent_to_ddns() {
        let bound = "192.168.1.10:4433".parse().unwrap();
        let inner = EndpointAddr::direct(bound);
        let outer = EndpointAddr::direct("203.0.113.10:50000".parse().unwrap());
        let agent = EndpointAddr::mediate(
            "198.51.100.1:3478".parse().unwrap(),
            "203.0.113.10:50000".parse().unwrap(),
        );
        let book = AddressBook::new();

        book.insert_inner(bound, inner).unwrap();
        book.insert_outer(bound, outer).unwrap();
        book.insert_agent(bound, agent).unwrap();

        assert_eq!(book.mdns_endpoints(bound).as_ref(), &[inner]);
        assert_eq!(book.ddns_endpoints().as_ref(), &[outer, agent]);

        book.remove_bound(bound);
        assert!(book.mdns_endpoints(bound).is_empty());
        assert!(book.ddns_endpoints().is_empty());
    }

    #[test]
    fn limits_agents_per_bound_address() {
        let bound = "192.168.1.10:4433".parse().unwrap();
        let book = AddressBook::new();

        for port in 3478..3481 {
            let endpoint = EndpointAddr::mediate(
                format!("198.51.100.1:{port}").parse().unwrap(),
                "203.0.113.10:50000".parse().unwrap(),
            );
            book.insert_agent(bound, endpoint).unwrap();
        }

        let fourth = EndpointAddr::mediate(
            "198.51.100.1:3481".parse().unwrap(),
            "203.0.113.10:50000".parse().unwrap(),
        );
        assert!(matches!(
            book.insert_agent(bound, fourth),
            Err(AddressBookError::TooManyAgents)
        ));
    }
}
