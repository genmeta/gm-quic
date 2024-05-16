use super::KeyPhaseBit;
use rustls::quic::{PacketKey, Secrets};
use std::sync::Arc;

pub struct OneRttPacketKeys {
    cur_key_phase: KeyPhaseBit,
    secrets: Secrets,
    remote_keys: [Option<Arc<PacketKey>>; 2],
    local: Arc<PacketKey>,
}

impl OneRttPacketKeys {
    pub fn new(remote: PacketKey, local: PacketKey, secret: Secrets) -> Self {
        Self {
            cur_key_phase: KeyPhaseBit::default(),
            secrets: secret,
            remote_keys: [Some(Arc::new(remote)), None],
            local: Arc::new(local),
        }
    }

    /// Key actively upgrades, which occurs when we want to actively change the key.
    pub fn update(&mut self) {
        self.cur_key_phase.toggle();
        let key_set = self.secrets.next_packet_keys();
        self.remote_keys[self.cur_key_phase.index()] = Some(Arc::new(key_set.remote));
        self.local = Arc::new(key_set.local);
    }

    /// Old key must be phased out within a certain period of time. If the old one don't go,
    /// the new ones won't come. If it is not phased out, it will be considered as new keys
    /// after actively changing the keys, leading to the failure of decrypting the data packets
    /// received from the other party.
    pub fn phase_out(&mut self) {
        self.remote_keys[(!self.cur_key_phase).index()].take();
    }

    /// Get the remote key to decrypt the incoming packet.
    /// If the key phase is not the current key phase, update the key.
    /// Returning Arc<PacketKey> is to encrypt and decrypt packets at the same time.
    /// Compared to &'a PacketKey, Arc<PacketKey> does not occupy mutable borrowing &mut self.
    pub fn get_remote(&mut self, key_phase: KeyPhaseBit, _pn: u64) -> Arc<PacketKey> {
        if key_phase != self.cur_key_phase && self.remote_keys[key_phase.index()].is_none() {
            self.update();
        }
        self.remote_keys[key_phase.index()].clone().unwrap()
    }

    /// Get the local key with the current key phase to encrypt the outgoing packet.
    /// Returning Arc<PacketKey> is to encrypt and decrypt packets at the same time.
    /// Compared to &'a PacketKey, Arc<PacketKey> does not occupy mutable borrowing &mut self.
    pub fn get_local(&self) -> (KeyPhaseBit, Arc<PacketKey>) {
        (self.cur_key_phase, self.local.clone())
    }
}
