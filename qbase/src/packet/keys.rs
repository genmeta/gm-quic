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
pub struct ArcKeys(Arc<Mutex<KeysState>>);

impl ArcKeys {
    #[inline]
    fn lock_guard(&self) -> MutexGuard<KeysState> {
        self.0.lock().unwrap()
    }

    /// Create a Pending state [`ArcKeys`].
    ///
    /// For a new Quic connection, initially only the Initial key is known, and the 0Rtt
    /// and Handshake keys are unknown.
    /// Therefore, the 0Rtt and Handshake keys can be created in a Pending state, waiting
    /// for key updates during the TLS handshake process.
    pub fn new_pending() -> Self {
        Self(Arc::new(KeysState::Pending(None).into()))
    }

    /// Create an [`ArcKeys`] with a specified [`rustls::quic::Keys`].
    pub fn with_keys(keys: Keys) -> Self {
        Self(Arc::new(KeysState::Ready(Arc::new(keys)).into()))
    }

    /// Asynchronously obtain the remote keys for removing header protection and packet decryption.
    ///
    /// Rreturn [`GetRemoteKeys`] implemented Future trait.
    ///
    /// ## Example
    ///
    /// The following is only a demonstration.
    /// Actually, removing header protection and decrypting eht packet are much more complex!
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
    pub fn get_remote_keys(&self) -> GetRemoteKeys {
        GetRemoteKeys(self.clone())
    }

    /// Get the encrypting keys.
    /// If the keys is not ready, return None.
    ///
    /// ## Example
    ///
    /// The following is only a demonstration.
    /// Actually, encrypting the packet and adding header protection are much more complex!
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
    pub fn get_local_keys(&self) -> Option<Arc<Keys>> {
        let state = self.lock_guard();
        match &*state {
            KeysState::Ready(keys) => Some(keys.clone()),
            _ => None,
        }
    }

    /// Set the keys to the [`ArcKeys`].
    ///
    /// As the TLS handshake progresses, corresponding key upgrades will be obtained,
    /// resulting in higher-level keys.
    /// These keys are set to the related [`ArcKeys`] through this method, and
    /// its internal waker will be awakened to notify the packet decryption task
    /// to continue, if the internal waker was registered.
    pub fn set_keys(&self, keys: Keys) {
        let mut state = self.lock_guard();
        match &mut *state {
            KeysState::Pending(waker) => {
                if let Some(waker) = waker.take() {
                    waker.wake();
                }
                *state = KeysState::Ready(Arc::new(keys));
            }
            KeysState::Ready(_) => panic!("set_keys called twice"),
            KeysState::Invalid => panic!("set_keys called after invalidation"),
        }
    }

    /// Retire the keys, which means that the keys are no longer available.
    ///
    /// This is used when the connection enters the closing state or draining state.
    /// Especially in the closing state, the return keys are used to generate the final packet
    /// containing the ConnectionClose frame, and decrypt the data packets received from the
    /// peer for a while.
    pub fn invalid(&self) -> Option<Arc<Keys>> {
        let mut state = self.lock_guard();
        match std::mem::replace(state.deref_mut(), KeysState::Invalid) {
            KeysState::Pending(waker) => {
                if let Some(waker) = waker {
                    waker.wake();
                }
                None
            }
            KeysState::Ready(keys) => Some(keys),
            KeysState::Invalid => unreachable!(),
        }
    }
}

/// To obtain the remote keys from [`ArcKeys`] for removing long header protection
/// and packet decryption.
pub struct GetRemoteKeys(ArcKeys);

impl Future for GetRemoteKeys {
    type Output = Option<Arc<Keys>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut keys = self.0.lock_guard();
        match &mut *keys {
            KeysState::Pending(waker) => {
                assert!(waker.is_none());
                *waker = Some(cx.waker().clone());
                Poll::Pending
            }
            KeysState::Ready(keys) => Poll::Ready(Some(keys.clone())),
            KeysState::Invalid => Poll::Ready(None),
        }
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

    /// Key actively updates occurs when we need to proactively change the key.
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

    /// Get the remote key to decrypt the incoming packet.
    /// If the key phase is not the current key phase, update the key.
    ///
    /// Return `Arc<PacketKey>` to decrypt the incoming packets.
    pub fn get_remote(&mut self, key_phase: KeyPhaseBit, _pn: u64) -> Arc<dyn PacketKey> {
        if key_phase != self.cur_phase && self.remote[key_phase.as_index()].is_none() {
            self.update();
        }
        self.remote[key_phase.as_index()].clone().unwrap()
    }

    /// Get the local key with the current key phase to encrypt the outgoing packet.
    ///
    /// Returning `Arc<PacketKey>` is to encrypt and decrypt packets at the same time.
    pub fn get_local(&self) -> (KeyPhaseBit, Arc<dyn PacketKey>) {
        (self.cur_phase, self.local.clone())
    }
}

/// The packet encryption and decryption keys for 1-RTT packets, which will still
/// change based on the KeyPhase bit in the receiving packet, or they can be update
/// it proactively locally.
///
/// For performance reasons, the second element of the tuple is the length of the
/// tag of the local packet key redundantly.
#[derive(Clone)]
pub struct ArcOneRttPacketKeys(Arc<(Mutex<OneRttPacketKeys>, usize)>);

impl ArcOneRttPacketKeys {
    /// Obtain exclusive access to the 1-RTT packet keys.
    /// During the exclusive period of encrypting or decrypting packets,
    /// the keys must not be updated elsewhere.
    pub fn lock_guard(&self) -> MutexGuard<OneRttPacketKeys> {
        self.0 .0.lock().unwrap()
    }

    /// Get the length of the tag of the packet key.
    ///
    /// For example, when collecting data to send, buffer needs to reserved
    /// the tag length space to fill in the integrity check code.
    /// After collecting the data, encryption will be performed, and exclusive
    /// access will be obtained during encryption.
    /// There is no need to acquire the lock at the beginning to get the tag
    /// length, because nothing might be sent later, and the task might be canceled.
    /// This would save the initial locking overhead.
    /// Keeping a redundant tag length that can be obtained without locking
    /// will improve lock performance.
    pub fn tag_len(&self) -> usize {
        self.0 .1
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
    fn lock_guard(&self) -> MutexGuard<OneRttKeysState> {
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
    pub fn set_keys(&self, keys: Keys, secrets: Secrets) {
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
    /// If the keys are not ready, return None.
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
    /// Rreturn [`GetRemoteKeys`] implemented Future trait.
    pub fn get_remote_keys(&self) -> GetRemoteOneRttKeys {
        GetRemoteOneRttKeys(self.clone())
    }
}

/// To obtain the remote key from [`ArcOneRttKeys`]` for removing 1-RTT header
/// protection and packet decryption.
pub struct GetRemoteOneRttKeys(ArcOneRttKeys);

impl Future for GetRemoteOneRttKeys {
    type Output = Option<(Arc<dyn HeaderProtectionKey>, ArcOneRttPacketKeys)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut keys = self.0.lock_guard();
        match &mut *keys {
            OneRttKeysState::Pending(waker) => {
                assert!(waker.is_none());
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
