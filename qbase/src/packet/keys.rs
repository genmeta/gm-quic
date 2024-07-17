use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use rustls::quic::{HeaderProtectionKey, Keys, PacketKey, Secrets};

use super::KeyPhaseBit;

#[derive(Clone)]
enum KeysState {
    Pending(Option<Waker>),
    Ready(Arc<Keys>),
    Invalid,
}

#[derive(Clone)]
pub struct ArcKeys(Arc<Mutex<KeysState>>);

impl ArcKeys {
    pub fn new_pending() -> Self {
        Self(Arc::new(Mutex::new(KeysState::Pending(None))))
    }

    pub fn with_keys(keys: Keys) -> Self {
        Self(Arc::new(Mutex::new(KeysState::Ready(Arc::new(keys)))))
    }

    pub fn get_remote_keys(&self) -> GetRemoteKeys {
        GetRemoteKeys(self.0.clone())
    }

    pub fn get_local_keys(&self) -> Option<Arc<Keys>> {
        let state = self.0.lock().unwrap();
        match &*state {
            KeysState::Ready(keys) => Some(keys.clone()),
            _ => None,
        }
    }

    pub fn set_keys(&self, keys: Keys) {
        let mut state = self.0.lock().unwrap();
        match &mut *state {
            KeysState::Pending(rx_waker) => {
                if let Some(waker) = rx_waker.take() {
                    waker.wake();
                }
                *state = KeysState::Ready(Arc::new(keys));
            }
            KeysState::Ready(_) => panic!("set_keys called twice"),
            KeysState::Invalid => panic!("set_keys called after invalidation"),
        }
    }

    pub fn invalid(&self) {
        let mut state = self.0.lock().unwrap();
        match &mut *state {
            KeysState::Pending(rx_waker) => {
                if let Some(waker) = rx_waker.take() {
                    waker.wake();
                }
                *state = KeysState::Invalid;
            }
            KeysState::Ready(_) => *state = KeysState::Invalid,
            KeysState::Invalid => {}
        }
    }

    pub fn is_invalid(&self) -> bool {
        matches!(&*self.0.lock().unwrap(), KeysState::Invalid)
    }
}

pub struct GetRemoteKeys(Arc<Mutex<KeysState>>);

impl Future for GetRemoteKeys {
    type Output = Option<Arc<Keys>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut keys = self.0.lock().unwrap();
        match &mut *keys {
            KeysState::Pending(rx_waker) => {
                assert!(rx_waker.is_none());
                *rx_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            KeysState::Ready(keys) => Poll::Ready(Some(keys.clone())),
            KeysState::Invalid => Poll::Ready(None),
        }
    }
}

enum OneRttKeysState {
    Pending(Option<Waker>),
    Ready {
        psk: (Arc<dyn HeaderProtectionKey>, Arc<dyn HeaderProtectionKey>),
        pk: Arc<Mutex<OneRttPacketKeys>>,
    },
    Invalid,
}

pub struct OneRttPacketKeys {
    cur_key_phase: KeyPhaseBit,
    secrets: Secrets,
    remote: [Option<Arc<dyn PacketKey>>; 2],
    local: Arc<dyn PacketKey>,
}

impl OneRttPacketKeys {
    fn new(remote: Box<dyn PacketKey>, local: Box<dyn PacketKey>, secrets: Secrets) -> Self {
        Self {
            cur_key_phase: KeyPhaseBit::default(),
            secrets,
            remote: [Some(Arc::from(remote)), None],
            local: Arc::from(local),
        }
    }

    /// Key actively upgrades, which occurs when we want to actively change the key.
    pub fn update(&mut self) {
        self.cur_key_phase.toggle();
        let key_set = self.secrets.next_packet_keys();
        self.remote[self.cur_key_phase.as_index()] = Some(Arc::from(key_set.remote));
        self.local = Arc::from(key_set.local);
    }

    /// Old key must be phased out within a certain period of time. If the old one don't go,
    /// the new ones won't come. If it is not phased out, it will be considered as new keys
    /// after actively changing the keys, leading to the failure of decrypting the data packets
    /// received from the other party.
    pub fn phase_out(&mut self) {
        self.remote[(!self.cur_key_phase).as_index()].take();
    }

    /// Get the remote key to decrypt the incoming packet.
    /// If the key phase is not the current key phase, update the key.
    /// Returning Arc<PacketKey> is to encrypt and decrypt packets at the same time.
    /// Compared to &'a PacketKey, Arc<PacketKey> does not occupy mutable borrowing &mut self.
    pub fn get_remote(&mut self, key_phase: KeyPhaseBit, _pn: u64) -> Arc<dyn PacketKey> {
        if key_phase != self.cur_key_phase && self.remote[key_phase.as_index()].is_none() {
            self.update();
        }
        self.remote[key_phase.as_index()].clone().unwrap()
    }

    /// Get the local key with the current key phase to encrypt the outgoing packet.
    /// Returning Arc<PacketKey> is to encrypt and decrypt packets at the same time.
    /// Compared to &'a PacketKey, Arc<PacketKey> does not occupy mutable borrowing &mut self.
    pub fn get_local(&self) -> (KeyPhaseBit, Arc<dyn PacketKey>) {
        (self.cur_key_phase, self.local.clone())
    }
}

#[derive(Clone)]
pub struct ArcOneRttKeys(Arc<Mutex<OneRttKeysState>>);

impl ArcOneRttKeys {
    pub fn new_pending() -> Self {
        Self(Arc::new(Mutex::new(OneRttKeysState::Pending(None))))
    }

    pub fn set_keys(&self, keys: Keys, secrets: Secrets) {
        let mut state = self.0.lock().unwrap();
        match &mut *state {
            OneRttKeysState::Pending(rx_waker) => {
                if let Some(waker) = rx_waker.take() {
                    waker.wake();
                }
                let psk = (Arc::from(keys.remote.header), Arc::from(keys.local.header));
                let pk = Arc::new(Mutex::new(OneRttPacketKeys::new(
                    keys.remote.packet,
                    keys.local.packet,
                    secrets,
                )));
                *state = OneRttKeysState::Ready { psk, pk };
            }
            OneRttKeysState::Ready { .. } => panic!("set_keys called twice"),
            OneRttKeysState::Invalid => panic!("set_keys called after invalidation"),
        }
    }

    pub fn invalid(&self) {
        let mut state = self.0.lock().unwrap();
        match &mut *state {
            OneRttKeysState::Pending(rx_waker) => {
                if let Some(waker) = rx_waker.take() {
                    waker.wake();
                }
                *state = OneRttKeysState::Invalid;
            }
            OneRttKeysState::Ready { .. } => *state = OneRttKeysState::Invalid,
            OneRttKeysState::Invalid => {}
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn get_local_keys(
        &self,
    ) -> Option<(Arc<dyn HeaderProtectionKey>, Arc<Mutex<OneRttPacketKeys>>)> {
        let mut keys = self.0.lock().unwrap();
        match &mut *keys {
            OneRttKeysState::Ready { psk, pk } => Some((psk.1.clone(), pk.clone())),
            _ => None,
        }
    }

    pub fn get_remote_keys(&self) -> GetRemoteOneRttKeys {
        GetRemoteOneRttKeys(self.0.clone())
    }

    pub fn is_invalid(&self) -> bool {
        !matches!(&*self.0.lock().unwrap(), OneRttKeysState::Invalid)
    }
}

pub struct GetRemoteOneRttKeys(Arc<Mutex<OneRttKeysState>>);

impl Future for GetRemoteOneRttKeys {
    type Output = Option<(Arc<dyn HeaderProtectionKey>, Arc<Mutex<OneRttPacketKeys>>)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut keys = self.0.lock().unwrap();
        match &mut *keys {
            OneRttKeysState::Pending(rx_waker) => {
                assert!(rx_waker.is_none());
                *rx_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            OneRttKeysState::Ready { psk, pk } => Poll::Ready(Some((psk.0.clone(), pk.clone()))),
            OneRttKeysState::Invalid => Poll::Ready(None),
        }
    }
}
