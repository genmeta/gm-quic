use std::{
    future::Future,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use futures::FutureExt;
use rustls::quic::{
    DirectionalKeys as RustlsDirectionalKeys, HeaderProtectionKey, Keys as RustlsKeys, PacketKey,
    Secrets,
};

/// Keys used to communicate in a single direction
#[derive(Clone)]
pub struct DirectionalKeys {
    /// Encrypts or decrypts a packet's headers
    pub header: Arc<dyn HeaderProtectionKey>,
    /// Encrypts or decrypts the payload of a packet
    pub packet: Arc<dyn PacketKey>,
}

impl From<RustlsDirectionalKeys> for DirectionalKeys {
    fn from(keys: RustlsDirectionalKeys) -> Self {
        Self {
            header: keys.header.into(),
            packet: keys.packet.into(),
        }
    }
}

/// Complete set of keys used to communicate with the peer
#[derive(Clone)]
pub struct Keys {
    /// Encrypts outgoing packets
    pub local: DirectionalKeys,
    /// Decrypts incoming packets
    pub remote: DirectionalKeys,
}

impl From<RustlsKeys> for Keys {
    fn from(keys: RustlsKeys) -> Self {
        Self {
            local: keys.local.into(),
            remote: keys.remote.into(),
        }
    }
}

use super::KeyPhaseBit;
use crate::sid::Role;

#[derive(Clone)]
enum KeysState<K> {
    Pending(Option<Waker>),
    Ready(K),
    Invalid,
}

impl<K> KeysState<K> {
    fn set(&mut self, keys: K) {
        match self {
            KeysState::Pending(waker) => {
                if let Some(waker) = waker.take() {
                    waker.wake();
                }
                *self = KeysState::Ready(keys);
            }
            KeysState::Ready(_) => unreachable!("KeysState::set called twice"),
            KeysState::Invalid => unreachable!("KeysState::set called after invalidation"),
        }
    }

    fn get(&mut self) -> Option<&K> {
        match self {
            KeysState::Ready(keys) => Some(keys),
            KeysState::Pending(..) | KeysState::Invalid => None,
        }
    }

    fn invalid(&mut self) -> Option<K> {
        match std::mem::replace(self, KeysState::Invalid) {
            KeysState::Pending(waker) => {
                if let Some(waker) = waker {
                    waker.wake();
                }
                None
            }
            KeysState::Ready(keys) => Some(keys),
            KeysState::Invalid => None,
        }
    }
}

impl<K: Unpin + Clone> Future for KeysState<K> {
    type Output = Option<K>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            KeysState::Pending(waker) => {
                if waker
                    .as_ref()
                    .is_some_and(|waker| !waker.will_wake(cx.waker()))
                {
                    unreachable!(
                        "Try to get remote keys from multiple tasks! This is a bug, please report it."
                    )
                }
                *waker = Some(cx.waker().clone());
                Poll::Pending
            }
            KeysState::Ready(keys) => Poll::Ready(Some(keys.clone())),
            KeysState::Invalid => Poll::Ready(None),
        }
    }
}

/// Long packet keys, for encryption and decryption keys for those long packets,
/// as well as keys for adding and removing long packet header protection.
///
/// - When sending, obtain the local keys for packet encryption and adding header protection.
///   If the keys are not ready, skip sending the packet of this level immidiately.
/// - When receiving a packet and decrypting it, obtain the remote keys for removing header
///   protection and packet decryption.
///   If the keys are not ready, wait asynchronously until the keys to be ready to continue.
///
/// ## Note
///
/// The keys for 1-RTT packets are a separate structure, see [`ArcOneRttKeys`].
#[derive(Clone)]
pub struct ArcKeys(Arc<Mutex<KeysState<Keys>>>);

impl ArcKeys {
    fn lock_guard(&self) -> MutexGuard<'_, KeysState<Keys>> {
        self.0.lock().unwrap()
    }

    /// Create a Pending state [`ArcKeys`].
    ///
    /// For a new Quic connection, initially only the Initial key is known, and the 0-RTT
    /// and Handshake keys are unknown.
    /// Therefore, the 0-RTT and Handshake keys can be created in a Pending state, waiting
    /// for updates during the TLS handshake process.
    pub fn new_pending() -> Self {
        Self(Arc::new(KeysState::Pending(None).into()))
    }

    /// Create an [`ArcKeys`] with a specified [`rustls::quic::Keys`].
    ///
    /// The initial keys are known at first, can use this method to create the [`ArcKeys`].
    pub fn with_keys(keys: Keys) -> Self {
        Self(Arc::new(KeysState::Ready(keys).into()))
    }

    /// Asynchronously obtain the remote keys for removing header protection and packet decryption.
    ///
    /// Rreturn [`GetRemoteKeys`], which implemented Future trait.
    ///
    /// ## Example
    ///
    /// The following is only a demonstration.
    /// In fact, removing header protection and decrypting packets are far more complex!
    ///
    /// ```
    /// use qbase::packet::keys::ArcKeys;
    ///
    /// async fn decrypt_demo(keys: ArcKeys, cipher_text: &mut [u8]) {
    ///     let Some(keys) = keys.get_remote_keys().await else {
    ///         return;
    ///     };
    ///
    ///     let hpk = keys.remote.header.as_ref();
    ///     let pk = keys.remote.packet.as_ref();
    ///
    ///     // use hpk to remove header protection...
    ///     // use pk to decrypt packet body...
    /// }
    /// ```
    pub fn get_remote_keys(&self) -> GetRemoteKeys<'_, Keys> {
        GetRemoteKeys(&self.0)
    }

    /// Get the local keys for packet encryption and adding header protection.
    /// If the keys is not ready, just return None immediately.
    ///
    /// ## Example
    ///
    /// The following is only a demonstration.
    /// In fact, encrypting packets and adding header protection are far more complex!
    ///
    /// ```
    /// use qbase::packet::keys::ArcKeys;
    ///
    /// fn encrypt_demo(keys: ArcKeys, plain_text: &mut [u8]) {
    ///     let Some(keys) = keys.get_local_keys() else {
    ///         return;
    ///     };
    ///
    ///     let hpk = keys.local.header.as_ref();
    ///     let pk = keys.local.packet.as_ref();
    ///
    ///     // use pk to encrypt packet body...
    ///     // use hpk to add header protection...
    /// }
    /// ```
    pub fn get_local_keys(&self) -> Option<Keys> {
        self.lock_guard().get().cloned()
    }

    /// Set the keys to the [`ArcKeys`].
    ///
    /// As the TLS handshake progresses, higher-level keys will be obtained.
    /// These keys are set to the related [`ArcKeys`] through this method, and
    /// its internal waker will be awakened to notify the packet decryption task
    /// to continue, if the internal waker was registered.
    pub fn set_keys(&self, keys: Keys) {
        self.lock_guard().set(keys);
    }

    /// Retire the keys, which means that the keys are no longer available.
    ///
    /// This is used when the connection enters the closing state or draining state.
    /// Especially in the closing state, the return keys are used to generate the final packet
    /// containing the ConnectionClose frame, and decrypt the data packets received from the
    /// peer for a while.
    pub fn invalid(&self) -> Option<Keys> {
        self.lock_guard().invalid()
    }
}

/// To obtain the remote keys from [`ArcKeys`] or [`ArcOneRttKeys`] for removing long header protection
/// and packet decryption.
pub struct GetRemoteKeys<'k, K>(&'k Mutex<KeysState<K>>);

impl<K: Unpin + Clone> Future for GetRemoteKeys<'_, K> {
    type Output = Option<K>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(self.0.lock().unwrap()).poll_unpin(cx)
    }
}

#[derive(Clone)]
pub struct ArcZeroRttKeys {
    role: Role,
    keys: Arc<Mutex<KeysState<DirectionalKeys>>>,
}

impl ArcZeroRttKeys {
    pub fn new_pending(role: Role) -> Self {
        Self {
            role,
            keys: Arc::new(Mutex::new(KeysState::Pending(None))),
        }
    }

    fn lock_guard(&self) -> MutexGuard<'_, KeysState<DirectionalKeys>> {
        self.keys.lock().unwrap()
    }

    pub fn set_keys(&self, keys: DirectionalKeys) {
        self.lock_guard().set(keys);
    }

    pub fn get_encrypt_keys(&self) -> Option<DirectionalKeys> {
        match self.role {
            Role::Client => self.lock_guard().get().cloned(),
            Role::Server => None,
        }
    }

    pub fn get_decrypt_keys(&self) -> Option<GetRemoteKeys<'_, DirectionalKeys>> {
        match self.role {
            Role::Client => None,
            Role::Server => Some(GetRemoteKeys(&self.keys)),
        }
    }

    pub fn invalid(&self) -> Option<DirectionalKeys> {
        self.lock_guard().invalid()
    }
}

/// The packet encryption and decryption keys for 1-RTT packets,
/// which will still change after negotiation between the two endpoints.
///
/// See [key update](https://www.rfc-editor.org/rfc/rfc9001#name-key-update)
/// of [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) for more details.
pub struct OneRttPacketKeys {
    cur_phase: KeyPhaseBit,
    secrets: Secrets,
    remote: [Option<Arc<dyn PacketKey>>; 2],
    local: Arc<dyn PacketKey>,
}

impl OneRttPacketKeys {
    /// Create new [`OneRttPacketKeys`].
    ///
    /// The TLS handshake session must exchange enough information to generate the 1-RTT keys.
    fn new(remote: Box<dyn PacketKey>, local: Box<dyn PacketKey>, secrets: Secrets) -> Self {
        Self {
            cur_phase: KeyPhaseBit::default(),
            secrets,
            remote: [Some(Arc::from(remote)), None],
            local: Arc::from(local),
        }
    }

    /// Proactively update the 1-RTT packet key locally.
    /// Or be informed by the peer to update the key.
    ///
    /// The key phase bit will be toggled and sent to the peer,
    /// informing the peer to update the key to next 1-RTT packet key too.
    pub fn update(&mut self) {
        self.cur_phase.toggle();
        let key_set = self.secrets.next_packet_keys();
        self.remote[self.cur_phase.as_index()] = Some(Arc::from(key_set.remote));
        self.local = Arc::from(key_set.local);
    }

    /// Old key must be phased out within a certain period of time.
    ///
    /// If the old one don't go, the new ones won't come.
    /// If it is not phased out, it will be considered as new keys and
    /// fail to decrypt the packet in future.
    pub fn phase_out(&mut self) {
        self.remote[(!self.cur_phase).as_index()].take();
    }

    /// Get the remote key to decrypt the incoming 1-RTT packet.
    /// If the key phase is not the current key phase, update the key, see [`Self::update`].
    ///
    /// Return `Arc<PacketKey>` to decrypt the incoming 1-RTT packet.
    pub fn get_remote(&mut self, key_phase: KeyPhaseBit, _pn: u64) -> Arc<dyn PacketKey> {
        if key_phase != self.cur_phase && self.remote[key_phase.as_index()].is_none() {
            self.update();
        }
        self.remote[key_phase.as_index()].clone().unwrap()
    }

    /// Get the local current key to encrypt the outgoing packet.
    ///
    /// Return `Arc<PacketKey>` to encrypt the outgoing 1-RTT packet.
    pub fn get_local(&self) -> (KeyPhaseBit, Arc<dyn PacketKey>) {
        (self.cur_phase, self.local.clone())
    }
}

/// The packet encryption and decryption keys for 1-RTT packets, which will still
/// change based on the KeyPhase bit in the receiving packet, or they can be update
/// it proactively locally.
///
/// For performance reasons, the second element of the tuple is the length of the
/// tag of the local packet key's underlying AEAD algorithm redundantly.
#[derive(Clone)]
pub struct ArcOneRttPacketKeys(Arc<(Mutex<OneRttPacketKeys>, usize)>);

impl ArcOneRttPacketKeys {
    /// Obtain exclusive access to the 1-RTT packet keys.
    /// During the exclusive period of encrypting or decrypting packets,
    /// the keys must not be updated elsewhere.
    pub fn lock_guard(&self) -> MutexGuard<'_, OneRttPacketKeys> {
        self.0.0.lock().unwrap()
    }

    /// Get the length of the tag of the packet key's underlying AEAD algorithm.
    ///
    /// For example, when collecting data to send, buffer needs to reserve
    /// the tag length space to fill in the integrity checksum codes.
    /// After collecting the data, encryption will be performed, and exclusive
    /// access will be obtained during encryption.
    /// There is no need to acquire the lock at the beginning to get the tag
    /// length, because nothing might be sent later, and the task might be canceled.
    /// This would save the initial locking overhead.
    /// Keeping a redundant tag length that can be obtained without locking
    /// will improve lock performance.
    pub fn tag_len(&self) -> usize {
        self.0.1
    }
}

/// The header protection keys for 1-RTT packets.
#[derive(Clone)]
pub struct HeaderProtectionKeys {
    pub local: Arc<dyn HeaderProtectionKey>,
    pub remote: Arc<dyn HeaderProtectionKey>,
}

enum OneRttKeysState {
    Pending(Option<Waker>),
    Ready {
        hpk: HeaderProtectionKeys,
        pk: ArcOneRttPacketKeys,
    },
    Invalid,
}

/// 1-RTT packet keys, for packet encryption and decryption for 1-RTT packets,
/// as well as keys for adding and removing 1-RTT packet header protection.
///
/// and its packet key will be updated.
///
/// Unlike [`ArcKeys`], the HeaderProtectionKey for 1-RTT keys does not change,
/// but the PacketKey may still be updated with changes in the KeyPhase bit.
/// Therefore, the HeaderProtectionKey and PacketKey need to be managed separately.
#[derive(Clone)]
pub struct ArcOneRttKeys(Arc<Mutex<OneRttKeysState>>);

impl ArcOneRttKeys {
    fn lock_guard(&self) -> MutexGuard<'_, OneRttKeysState> {
        self.0.lock().unwrap()
    }

    /// Create a Pending state [`ArcOneRttKeys`], waiting for the keys being ready
    /// from TLS handshaking.
    pub fn new_pending() -> Self {
        Self(Arc::new(OneRttKeysState::Pending(None).into()))
    }

    /// Set the keys to the [`ArcOneRttKeys`].
    ///
    /// As the TLS handshake progresses, 1-RTT keys will finally be obtained.
    /// And then its internal waker will be awakened to notify the packet
    /// decryption task to continue, if the internal waker was registered.
    pub fn set_keys(&self, keys: RustlsKeys, secrets: Secrets) {
        let mut state = self.lock_guard();
        match &mut *state {
            OneRttKeysState::Pending(waker) => {
                let hpk = HeaderProtectionKeys {
                    local: Arc::from(keys.local.header),
                    remote: Arc::from(keys.remote.header),
                };
                let tag_len = keys.local.packet.tag_len();
                let pk = ArcOneRttPacketKeys(Arc::new((
                    Mutex::new(OneRttPacketKeys::new(
                        keys.remote.packet,
                        keys.local.packet,
                        secrets,
                    )),
                    tag_len,
                )));
                if let Some(w) = waker.take() {
                    w.wake();
                }
                *state = OneRttKeysState::Ready { hpk, pk };
            }
            OneRttKeysState::Ready { .. } => panic!("set_keys called twice"),
            OneRttKeysState::Invalid => panic!("set_keys called after invalidation"),
        }
    }

    pub fn invalid(&self) -> Option<(HeaderProtectionKeys, ArcOneRttPacketKeys)> {
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

    /// Get the local keys for packet encryption and adding header protection.
    /// If the keys are not ready, just return None immediately.
    ///
    /// Return a tuple of HeaderProtectionKey and OneRttPacketKeys.  
    /// The OneRttPacketKeys need to be locked during the entire packet encryption process.
    pub fn get_local_keys(&self) -> Option<(Arc<dyn HeaderProtectionKey>, ArcOneRttPacketKeys)> {
        let mut keys = self.lock_guard();
        match &mut *keys {
            OneRttKeysState::Ready { hpk, pk, .. } => Some((hpk.local.clone(), pk.clone())),
            _ => None,
        }
    }

    /// Asynchronously obtain the remote keys for removing header protection and packet decryption.
    ///
    /// Rreturn [`GetRemoteKeys`], which implemented the Future trait.
    pub fn get_remote_keys(&self) -> GetRemoteOneRttKeys<'_> {
        GetRemoteOneRttKeys(self)
    }
}

/// To obtain the remote key from [`ArcOneRttKeys`]` for removing 1-RTT header
/// protection and packet decryption.
pub struct GetRemoteOneRttKeys<'k>(&'k ArcOneRttKeys);

impl Future for GetRemoteOneRttKeys<'_> {
    type Output = Option<(Arc<dyn HeaderProtectionKey>, ArcOneRttPacketKeys)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut keys = self.0.lock_guard();
        match &mut *keys {
            OneRttKeysState::Pending(waker) => {
                if waker
                    .as_ref()
                    .is_some_and(|waker| !waker.will_wake(cx.waker()))
                {
                    unreachable!(
                        "Try to get remote keys from multiple tasks! This is a bug, please report it."
                    )
                }
                *waker = Some(cx.waker().clone());
                Poll::Pending
            }
            OneRttKeysState::Ready { hpk, pk, .. } => {
                Poll::Ready(Some((hpk.remote.clone(), pk.clone())))
            }
            OneRttKeysState::Invalid => Poll::Ready(None),
        }
    }
}
