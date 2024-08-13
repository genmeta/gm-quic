use std::{
    future::Future,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
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
    fn lock_guard(&self) -> MutexGuard<KeysState> {
        self.0.lock().unwrap()
    }

    pub fn new_pending() -> Self {
        Self(Arc::new(KeysState::Pending(None).into()))
    }

    pub fn with_keys(keys: Keys) -> Self {
        Self(Arc::new(KeysState::Ready(Arc::new(keys)).into()))
    }

    pub fn get_remote_keys(&self) -> GetRemoteKeys {
        GetRemoteKeys(self.clone())
    }

    pub fn get_local_keys(&self) -> Option<Arc<Keys>> {
        let state = self.lock_guard();
        match &*state {
            KeysState::Ready(keys) => Some(keys.clone()),
            _ => None,
        }
    }

    pub fn set_keys(&self, keys: Keys) {
        let mut state = self.lock_guard();
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

    /// Invalidate the keys, which means that the keys are no longer available.
    /// This is used when the connection enters the closing state or draining state.
    /// Especially in the closing state, the return keys are used to generate the final packet
    /// containing the ConnectionClose frame, and decrypt the data packets received from the
    /// peer for a while.
    pub fn invalid(&self) -> Option<Arc<Keys>> {
        let mut state = self.lock_guard();
        match std::mem::replace(state.deref_mut(), KeysState::Invalid) {
            KeysState::Pending(rx_waker) => {
                if let Some(waker) = rx_waker {
                    waker.wake();
                }
                None
            }
            KeysState::Ready(keys) => Some(keys),
            KeysState::Invalid => unreachable!(),
        }
    }
}

pub struct GetRemoteKeys(ArcKeys);

impl Future for GetRemoteKeys {
    type Output = Option<Arc<Keys>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut keys = self.0.lock_guard();
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
pub struct ArcOneRttPacketKeys(Arc<Mutex<OneRttPacketKeys>>);

impl ArcOneRttPacketKeys {
    pub fn lock_guard(&self) -> MutexGuard<OneRttPacketKeys> {
        self.0.lock().unwrap()
    }
}

#[derive(Clone)]
pub struct ArcHeaderProtectionKeys {
    pub local: Arc<dyn HeaderProtectionKey>,
    pub remote: Arc<dyn HeaderProtectionKey>,
}

enum OneRttKeysState {
    Pending(Option<Waker>),
    Ready {
        hpk: ArcHeaderProtectionKeys,
        pk: ArcOneRttPacketKeys,
    },
    Invalid,
}

#[derive(Clone)]
pub struct ArcOneRttKeys(Arc<Mutex<OneRttKeysState>>);

impl ArcOneRttKeys {
    fn lock_guard(&self) -> MutexGuard<OneRttKeysState> {
        self.0.lock().unwrap()
    }

    pub fn new_pending() -> Self {
        Self(Arc::new(OneRttKeysState::Pending(None).into()))
    }

    pub fn set_keys(&self, keys: Keys, secrets: Secrets) {
        let mut state = self.lock_guard();
        match &mut *state {
            OneRttKeysState::Pending(rx_waker) => {
                if let Some(waker) = rx_waker.take() {
                    waker.wake();
                }
                let (remote_hpk, local_hpk) =
                    (Arc::from(keys.remote.header), Arc::from(keys.local.header));
                let hpk = ArcHeaderProtectionKeys {
                    remote: remote_hpk,
                    local: local_hpk,
                };
                let pk = ArcOneRttPacketKeys(Arc::new(Mutex::new(OneRttPacketKeys::new(
                    keys.remote.packet,
                    keys.local.packet,
                    secrets,
                ))));
                *state = OneRttKeysState::Ready { hpk, pk };
            }
            OneRttKeysState::Ready { .. } => panic!("set_keys called twice"),
            OneRttKeysState::Invalid => panic!("set_keys called after invalidation"),
        }
    }

    pub fn invalid(&self) -> Option<(ArcHeaderProtectionKeys, ArcOneRttPacketKeys)> {
        let mut state = self.lock_guard();
        match std::mem::replace(state.deref_mut(), OneRttKeysState::Invalid) {
            OneRttKeysState::Pending(rx_waker) => {
                if let Some(waker) = rx_waker {
                    waker.wake();
                }
                None
            }
            OneRttKeysState::Ready { hpk, pk } => Some((hpk, pk)),
            OneRttKeysState::Invalid => unreachable!(),
        }
    }

    pub fn get_local_keys(&self) -> Option<(Arc<dyn HeaderProtectionKey>, ArcOneRttPacketKeys)> {
        let mut keys = self.lock_guard();
        match &mut *keys {
            OneRttKeysState::Ready { hpk, pk, .. } => Some((hpk.local.clone(), pk.clone())),
            _ => None,
        }
    }

    pub fn get_remote_keys(&self) -> GetRemoteOneRttKeys {
        GetRemoteOneRttKeys(self.clone())
    }
}

pub struct GetRemoteOneRttKeys(ArcOneRttKeys);

impl Future for GetRemoteOneRttKeys {
    type Output = Option<(Arc<dyn HeaderProtectionKey>, ArcOneRttPacketKeys)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut keys = self.0.lock_guard();
        match &mut *keys {
            OneRttKeysState::Pending(rx_waker) => {
                assert!(rx_waker.is_none());
                *rx_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            OneRttKeysState::Ready { hpk, pk, .. } => {
                Poll::Ready(Some((hpk.remote.clone(), pk.clone())))
            }
            OneRttKeysState::Invalid => Poll::Ready(None),
        }
    }
}
