use super::KeyPhaseBit;
use rustls::quic::{HeaderProtectionKey, Keys, PacketKey, Secrets};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

#[derive(Clone)]
enum KeysState {
    Pending {
        rx_waker: Option<Waker>,
        tx_waker: Option<Waker>,
    },
    Ready(Arc<Keys>),
    Expired,
}

#[derive(Clone)]
pub struct ArcKeys(Arc<Mutex<KeysState>>);

impl ArcKeys {
    pub fn new_pending() -> Self {
        Self(Arc::new(Mutex::new(KeysState::Pending {
            rx_waker: None,
            tx_waker: None,
        })))
    }

    pub fn with_keys(keys: Keys) -> Self {
        Self(Arc::new(Mutex::new(KeysState::Ready(Arc::new(keys)))))
    }

    pub fn get_remote_keys(&self) -> GetRemoteKeys {
        GetRemoteKeys(self.0.clone())
    }

    pub fn get_local_keys(&self) -> GetLocalKeys {
        GetLocalKeys(self.0.clone())
    }

    pub fn set_keys(&self, keys: Keys) {
        let mut state = self.0.lock().unwrap();
        match &mut *state {
            KeysState::Pending { rx_waker, tx_waker } => {
                if let Some(waker) = rx_waker.take() {
                    waker.wake();
                }
                if let Some(waker) = tx_waker.take() {
                    waker.wake();
                }
                *state = KeysState::Ready(Arc::new(keys));
            }
            KeysState::Ready(_) => panic!("set_keys called twice"),
            KeysState::Expired => panic!("set_keys called after expiration"),
        }
    }

    pub fn expire(&self) {
        let mut state = self.0.lock().unwrap();
        match &mut *state {
            KeysState::Pending { rx_waker, tx_waker } => {
                if let Some(waker) = rx_waker.take() {
                    waker.wake();
                }
                if let Some(waker) = tx_waker.take() {
                    waker.wake();
                }
                *state = KeysState::Expired;
            }
            KeysState::Ready(_) => *state = KeysState::Expired,
            KeysState::Expired => {}
        }
    }
}

pub struct GetRemoteKeys(Arc<Mutex<KeysState>>);

impl Future for GetRemoteKeys {
    type Output = Option<Arc<Keys>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut keys = self.0.lock().unwrap();
        match &mut *keys {
            KeysState::Pending { rx_waker, .. } => {
                assert!(rx_waker.is_none());
                *rx_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            KeysState::Ready(keys) => Poll::Ready(Some(keys.clone())),
            KeysState::Expired => Poll::Ready(None),
        }
    }
}

pub struct GetLocalKeys(Arc<Mutex<KeysState>>);

impl Future for GetLocalKeys {
    type Output = Option<Arc<Keys>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut keys = self.0.lock().unwrap();
        match &mut *keys {
            KeysState::Pending { tx_waker, .. } => {
                assert!(tx_waker.is_none());
                *tx_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            KeysState::Ready(keys) => Poll::Ready(Some(keys.clone())),
            KeysState::Expired => Poll::Ready(None),
        }
    }
}

enum OneRttKeysState {
    Pending {
        rx_waker: Option<Waker>,
        tx_waker: Option<Waker>,
    },
    Ready {
        psk: (Arc<HeaderProtectionKey>, Arc<HeaderProtectionKey>),
        pk: Arc<Mutex<OneRttPacketKeys>>,
    },
}

pub struct OneRttPacketKeys {
    cur_key_phase: KeyPhaseBit,
    secrets: Secrets,
    remote: [Option<Arc<PacketKey>>; 2],
    local: Arc<PacketKey>,
}

impl OneRttPacketKeys {
    fn new(remote: PacketKey, local: PacketKey, secret: Secrets) -> Self {
        Self {
            cur_key_phase: KeyPhaseBit::default(),
            secrets: secret,
            remote: [Some(Arc::new(remote)), None],
            local: Arc::new(local),
        }
    }

    /// Key actively upgrades, which occurs when we want to actively change the key.
    pub fn update(&mut self) {
        self.cur_key_phase.toggle();
        let key_set = self.secrets.next_packet_keys();
        self.remote[self.cur_key_phase.index()] = Some(Arc::new(key_set.remote));
        self.local = Arc::new(key_set.local);
    }

    /// Old key must be phased out within a certain period of time. If the old one don't go,
    /// the new ones won't come. If it is not phased out, it will be considered as new keys
    /// after actively changing the keys, leading to the failure of decrypting the data packets
    /// received from the other party.
    pub fn phase_out(&mut self) {
        self.remote[(!self.cur_key_phase).index()].take();
    }

    /// Get the remote key to decrypt the incoming packet.
    /// If the key phase is not the current key phase, update the key.
    /// Returning Arc<PacketKey> is to encrypt and decrypt packets at the same time.
    /// Compared to &'a PacketKey, Arc<PacketKey> does not occupy mutable borrowing &mut self.
    pub fn get_remote(&mut self, key_phase: KeyPhaseBit, _pn: u64) -> Arc<PacketKey> {
        if key_phase != self.cur_key_phase && self.remote[key_phase.index()].is_none() {
            self.update();
        }
        self.remote[key_phase.index()].clone().unwrap()
    }

    /// Get the local key with the current key phase to encrypt the outgoing packet.
    /// Returning Arc<PacketKey> is to encrypt and decrypt packets at the same time.
    /// Compared to &'a PacketKey, Arc<PacketKey> does not occupy mutable borrowing &mut self.
    pub fn get_local(&self) -> (KeyPhaseBit, Arc<PacketKey>) {
        (self.cur_key_phase, self.local.clone())
    }
}

#[derive(Clone)]
pub struct ArcOneRttKeys(Arc<Mutex<OneRttKeysState>>);

impl ArcOneRttKeys {
    pub fn new_pending() -> Self {
        Self(Arc::new(Mutex::new(OneRttKeysState::Pending {
            rx_waker: None,
            tx_waker: None,
        })))
    }

    pub fn set_keys(&mut self, keys: Keys, secret: Secrets) {
        let mut state = self.0.lock().unwrap();
        match &mut *state {
            OneRttKeysState::Pending { rx_waker, tx_waker } => {
                if let Some(waker) = rx_waker.take() {
                    waker.wake();
                }
                if let Some(waker) = tx_waker.take() {
                    waker.wake();
                }
                let psk = (Arc::new(keys.remote.header), Arc::new(keys.local.header));
                let pk = Arc::new(Mutex::new(OneRttPacketKeys::new(
                    keys.remote.packet,
                    keys.local.packet,
                    secret,
                )));
                *state = OneRttKeysState::Ready { psk, pk };
            }
            OneRttKeysState::Ready { .. } => panic!("set_keys called twice"),
        }
    }

    pub fn packet_keys(&self) -> Option<Arc<Mutex<OneRttPacketKeys>>> {
        let state = self.0.lock().unwrap();
        match &*state {
            OneRttKeysState::Ready { pk, .. } => Some(pk.clone()),
            _ => None,
        }
    }

    pub fn get_local_keys(&self) -> GetLocalOneRttKeys {
        GetLocalOneRttKeys(self.0.clone())
    }

    pub fn get_remote_keys(&self) -> GetRemoteOneRttKeys {
        GetRemoteOneRttKeys(self.0.clone())
    }
}

pub struct GetRemoteOneRttKeys(Arc<Mutex<OneRttKeysState>>);

impl Future for GetRemoteOneRttKeys {
    type Output = (Arc<HeaderProtectionKey>, Arc<Mutex<OneRttPacketKeys>>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut keys = self.0.lock().unwrap();
        match &mut *keys {
            OneRttKeysState::Pending { rx_waker, .. } => {
                assert!(rx_waker.is_none());
                *rx_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            OneRttKeysState::Ready { psk, pk } => Poll::Ready((psk.0.clone(), pk.clone())),
        }
    }
}

pub struct GetLocalOneRttKeys(Arc<Mutex<OneRttKeysState>>);

impl Future for GetLocalOneRttKeys {
    type Output = (Arc<HeaderProtectionKey>, Arc<Mutex<OneRttPacketKeys>>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut keys = self.0.lock().unwrap();
        match &mut *keys {
            OneRttKeysState::Pending { tx_waker, .. } => {
                assert!(tx_waker.is_none());
                *tx_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            OneRttKeysState::Ready { psk, pk } => Poll::Ready((psk.1.clone(), pk.clone())),
        }
    }
}
