use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    ops::{DerefMut, Range},
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
use crate::{
    error::{ErrorKind, QuicError},
    role::Role,
};

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
    /// Returns [`GetRemoteKeys`], which implements the Future trait.
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
    pub fn invalidate(&self) -> Option<Keys> {
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

    pub fn invalidate(&self) -> Option<DirectionalKeys> {
        self.lock_guard().invalid()
    }
}

/// The packet encryption and decryption keys for 1-RTT packets,
/// which will still change after negotiation between the two endpoints.
///
/// See [key update](https://www.rfc-editor.org/rfc/rfc9001#name-key-update)
/// of [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetKeyError {
    Retired,
    Unknown,
}

/// Entry in the 1-RTT key update window.
/// Each entry represents a key generation with both send and receive keys.
#[derive(Clone)]
pub struct KeyEntry {
    /// Generation counter (0, 1, 2, ...)
    pub generation: u64,
    /// Send key for outgoing packets
    pub local_key: Arc<dyn PacketKey>,
    /// Receive key for incoming packets
    pub remote_key: Arc<dyn PacketKey>,
    /// Record received packet number range for this key generation
    pub rcvd_pn_range: Option<Range<u64>>,
}

impl KeyEntry {
    fn new(generation: u64, local_key: Arc<dyn PacketKey>, remote_key: Arc<dyn PacketKey>) -> Self {
        Self {
            generation,
            local_key,
            remote_key,
            rcvd_pn_range: None,
        }
    }

    /// Update the received packet number range when a packet is successfully decrypted.
    fn update_rcvd_pn(&mut self, pn: u64) {
        match &mut self.rcvd_pn_range {
            None => self.rcvd_pn_range = Some(pn..pn + 1),
            Some(range) => {
                range.start = range.start.min(pn);
                range.end = range.end.max(pn + 1);
            }
        }
    }
}

pub struct OneRttPacketKeys {
    /// Key update counter, incremented on each update
    counter: u64,
    /// Ordered window of key entries (max 3 generations)
    keys: VecDeque<KeyEntry>,
    /// Secrets for derive next key pair
    secrets: Option<Secrets>,
    /// Current key phase bit
    cur_phase: KeyPhaseBit,
    /// Sent packet number ranges for each generation (for ACK tracking)
    sent_pn_ranges: HashMap<u64, Range<u64>>,
    /// Largest acknowledged packet number in 1-RTT space
    largest_acked_pn: Option<u64>,
    /// Map packet number to its generation
    sent_pn_stage: HashMap<u64, u64>,
    /// Count of unacked packets in each generation
    outstanding_pn_count: HashMap<u64, usize>,
    /// Consecutive decryption failures
    contiguous_decrypt_failures: u32,
}

/// Result of trying to decrypt with one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptAttemptResult {
    /// Decryption succeeded and returned plaintext body length.
    Success(usize),
    /// Decryption failed, but caller should continue trying other keys.
    ContinueTrying,
    /// Decryption failed and failure threshold is exceeded.
    GiveUp,
}

impl OneRttPacketKeys {
    /// Maximum number of consecutive decryption failures before giving up
    const MAX_CONTIGUOUS_DECRYPT_FAILURES: u32 = 3;

    /// Create new [`OneRttPacketKeys`].
    ///
    /// The TLS handshake session must exchange enough information to generate the 1-RTT keys.
    fn new(remote: Box<dyn PacketKey>, local: Box<dyn PacketKey>, secrets: Secrets) -> Self {
        let sk: Arc<dyn PacketKey> = Arc::from(local);
        let rk: Arc<dyn PacketKey> = Arc::from(remote);

        let mut keys = VecDeque::new();
        let entry = KeyEntry::new(0, sk.clone(), rk);
        keys.push_back(entry);

        Self {
            counter: 0,
            keys,
            secrets: Some(secrets),
            cur_phase: KeyPhaseBit::default(),
            sent_pn_ranges: HashMap::new(),
            largest_acked_pn: None,
            sent_pn_stage: HashMap::new(),
            outstanding_pn_count: HashMap::new(),
            contiguous_decrypt_failures: 0,
        }
    }

    /// Get the local key for encrypting outgoing packets.
    ///
    /// Returns (generation, key_phase, packet_key).
    fn get_local_key(&self) -> (u64, KeyPhaseBit, Arc<dyn PacketKey>) {
        let entry = self.keys.back().expect("keys should not be empty");
        (entry.generation, self.cur_phase, entry.local_key.clone())
    }

    /// Get candidate generations based on key phase bit.
    fn candidate_generations(&self, key_phase: KeyPhaseBit) -> [Option<u64>; 2] {
        if let Some(latest) = self.keys.back().map(|e| e.generation) {
            if key_phase == self.cur_phase {
                [Some(latest), latest.checked_sub(2)]
            } else {
                [latest.checked_sub(1), latest.checked_add(1)]
            }
        } else {
            [None, None]
        }
    }

    /// Returns true if the local endpoint is ready to initiate a key update on send path.
    ///
    /// Readiness means at least one packet from the current generation was acknowledged,
    /// which avoids rotating too early before the peer has confirmed current keys.
    fn is_send_key_update_ready(&self) -> bool {
        let latest_gen = self.keys.back().map(|e| e.generation).unwrap_or(0);
        let Some(min_sent_pn) = self.sent_pn_ranges.get(&latest_gen).map(|r| r.start) else {
            return false;
        };
        let Some(largest_acked) = self.largest_acked_pn else {
            return false;
        };
        largest_acked >= min_sent_pn
    }

    /// Derive and install the next key generation.
    ///
    /// This advances key phase, appends a new generation, and keeps only recent generations.
    fn rotate_to_next_key_generation(&mut self) {
        let key_set = self
            .secrets
            .as_mut()
            .expect("1-RTT secrets must exist when updating keys")
            .next_packet_keys();
        self.counter += 1;

        let entry = KeyEntry::new(
            self.counter,
            Arc::from(key_set.local),
            Arc::from(key_set.remote),
        );

        self.keys.push_back(entry);
        while self.keys.len() > 3 {
            self.keys.pop_front();
        }

        self.cur_phase.toggle();
    }

    /// When a packet in generation i is acked, we know the peer has received
    /// a packet encrypted with key i, confirming the key update.
    fn apply_packet_acked(
        &mut self,
        pn: u64,
        largest_ack: u64,
        rcvd_generation: Option<u64>,
    ) -> Result<(), QuicError> {
        self.largest_acked_pn = Some(
            self.largest_acked_pn
                .map_or(largest_ack, |cur| cur.max(largest_ack)),
        );

        let Some(stage) = self.sent_pn_stage.remove(&pn) else {
            return Ok(());
        };

        if let Some(rcvd_generation) = rcvd_generation
            && stage > rcvd_generation
        {
            return Err(QuicError::with_default_fty(
                ErrorKind::KeyUpdate,
                "peer acknowledged new-key packet with older key phase",
            ));
        }

        let Some(count) = self.outstanding_pn_count.get_mut(&stage) else {
            return Ok(());
        };

        *count = count.saturating_sub(1);
        if *count == 0 {
            self.outstanding_pn_count.remove(&stage);
        }
        Ok(())
    }

    /// Record sent packet number for key update tracking
    fn track_packet_sent(&mut self, generation: u64, pn: u64) {
        let entry = self.sent_pn_ranges.entry(generation).or_insert(pn..pn);
        entry.start = entry.start.min(pn);
        entry.end = entry.end.max(pn + 1);

        if let Some(old_stage) = self.sent_pn_stage.insert(pn, generation)
            && let Some(count) = self.outstanding_pn_count.get_mut(&old_stage)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.outstanding_pn_count.remove(&old_stage);
            }
        }

        *self.outstanding_pn_count.entry(generation).or_default() += 1;
    }

    /// Get the remote packet key for a specific generation.
    ///
    /// Returns `Some(key)` if the remote key for the given generation exists.
    /// Returns `None` if the generation is the next expected one (key not yet derived).
    /// Returns `Err` if the generation is invalid or has been discarded.
    fn get_remote_key_for_generation(
        &self,
        generation: u64,
    ) -> Result<Option<Arc<dyn PacketKey>>, GetKeyError> {
        for entry in self.keys.iter() {
            if entry.generation == generation {
                return Ok(Some(entry.remote_key.clone()));
            }
        }

        if let Some(latest) = self.keys.back().map(|e| e.generation) {
            if generation == latest + 1 {
                return Ok(None);
            }
        }

        Err(GetKeyError::Unknown)
    }

    /// Passive update in response to peer-initiated key phase change
    fn update_by_peer(&mut self) -> Result<(), QuicError> {
        if let Some(latest) = self.keys.back()
            && latest.rcvd_pn_range.is_none()
            && latest.generation > 0
        {
            return Err(QuicError::with_default_fty(
                ErrorKind::KeyUpdate,
                "received consecutive peer key updates before confirming prior update",
            ));
        }

        self.rotate_to_next_key_generation();
        Ok(())
    }

    /// Called when a packet is successfully decrypted with key of generation i.
    ///
    /// This marks the generation as confirmed by received data and updates the pn range.
    fn on_packet_decrypted(&mut self, rcvd_pn: u64, generation: u64) -> Result<(), QuicError> {
        let max_newer_pn = self
            .keys
            .iter()
            .filter(|entry| entry.generation > generation)
            .filter_map(|entry| entry.rcvd_pn_range.as_ref().map(|r| r.end - 1))
            .max();

        if let Some(max_newer_pn) = max_newer_pn
            && rcvd_pn > max_newer_pn
        {
            return Err(QuicError::with_default_fty(
                ErrorKind::KeyUpdate,
                "key downgrade detected: higher packet number decrypted with old key",
            ));
        }

        for entry in self.keys.iter_mut() {
            if entry.generation == generation {
                entry.update_rcvd_pn(rcvd_pn);
                break;
            }
        }

        self.contiguous_decrypt_failures = 0;
        Ok(())
    }

    /// Called when packet decryption fails with key of generation i.
    ///
    /// Returns true if we should give up (threshold exceeded), false otherwise.
    fn on_packet_decrypt_failed(&mut self) -> bool {
        self.contiguous_decrypt_failures += 1;
        self.contiguous_decrypt_failures > Self::MAX_CONTIGUOUS_DECRYPT_FAILURES
    }

    /// Handle the result of one decryption attempt and update key state.
    fn apply_decrypt_attempt(
        &mut self,
        generation: u64,
        decoded_pn: u64,
        decrypt_result: Result<usize, ()>,
    ) -> Result<DecryptAttemptResult, QuicError> {
        match decrypt_result {
            Ok(body_length) => {
                self.on_packet_decrypted(decoded_pn, generation)?;
                Ok(DecryptAttemptResult::Success(body_length))
            }
            Err(_) => {
                let reached_threshold = self.on_packet_decrypt_failed();
                if reached_threshold {
                    Ok(DecryptAttemptResult::GiveUp)
                } else {
                    Ok(DecryptAttemptResult::ContinueTrying)
                }
            }
        }
    }

    /// Get all candidate keys to try for decryption, in order of preference.
    ///
    /// Returns an iterator of (generation, key) tuples, and an optional next_generation
    /// that may need key update.
    fn collect_decrypt_key_candidates(
        &self,
        decoded_pn: u64,
        key_phase: KeyPhaseBit,
    ) -> (Vec<(u64, Arc<dyn PacketKey>)>, Option<u64>) {
        let mut candidates = Vec::new();
        let mut next_generation = None;

        // First, try primary key by packet number range
        for entry in self.keys.iter() {
            if let Some(range) = &entry.rcvd_pn_range {
                if decoded_pn >= range.start && decoded_pn < range.end {
                    let expected_phase = if entry.generation % 2 == 0 {
                        KeyPhaseBit::Zero
                    } else {
                        KeyPhaseBit::One
                    };
                    if key_phase == expected_phase {
                        candidates.push((entry.generation, entry.remote_key.clone()));
                        return (candidates, None);
                    }
                }
            }
        }

        // Try candidate generations
        for generation in self.candidate_generations(key_phase).into_iter().flatten() {
            match self.get_remote_key_for_generation(generation) {
                Ok(Some(key)) => candidates.push((generation, key)),
                Ok(None) => {
                    if next_generation.is_none() {
                        next_generation = Some(generation);
                    }
                }
                Err(_) => {}
            }
        }

        (candidates, next_generation)
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
    fn lock_guard(&self) -> MutexGuard<'_, OneRttPacketKeys> {
        self.0.0.lock().unwrap()
    }

    /// Update key phase if possible and return current local packet key material for sending.
    pub fn update_and_get_local_key(&self) -> (u64, KeyPhaseBit, Arc<dyn PacketKey>) {
        let mut keys = self.lock_guard();
        if keys.is_send_key_update_ready() {
            keys.rotate_to_next_key_generation();
        }
        keys.get_local_key()
    }

    /// Record a sent packet for key update tracking.
    pub fn on_packet_sent(&self, generation: u64, pn: u64) {
        self.lock_guard().track_packet_sent(generation, pn);
    }

    /// Handle ACK feedback for key update tracking.
    pub fn on_packet_acked(
        &self,
        pn: u64,
        largest_ack: u64,
        rcvd_generation: Option<u64>,
    ) -> Result<(), QuicError> {
        self.lock_guard()
            .apply_packet_acked(pn, largest_ack, rcvd_generation)
    }

    /// Get decryption candidate keys in preference order.
    pub fn get_candidate_keys_for_decryption(
        &self,
        decoded_pn: u64,
        key_phase: KeyPhaseBit,
    ) -> (Vec<(u64, Arc<dyn PacketKey>)>, Option<u64>) {
        self.lock_guard()
            .collect_decrypt_key_candidates(decoded_pn, key_phase)
    }

    /// Get remote key for generation; if generation is the next one, passively update once.
    pub fn resolve_remote_key_for_generation(
        &self,
        generation: u64,
    ) -> Result<Option<Arc<dyn PacketKey>>, QuicError> {
        let mut keys = self.lock_guard();
        match keys.get_remote_key_for_generation(generation) {
            Ok(Some(key)) => Ok(Some(key)),
            Ok(None) => {
                keys.update_by_peer()?;
                Ok(keys
                    .get_remote_key_for_generation(generation)
                    .ok()
                    .flatten())
            }
            Err(_) => Ok(None),
        }
    }

    /// Update decryption-related key state by one decryption attempt result.
    pub fn record_decrypt_attempt(
        &self,
        generation: u64,
        decoded_pn: u64,
        decrypt_result: Result<usize, ()>,
    ) -> Result<DecryptAttemptResult, QuicError> {
        self.lock_guard()
            .apply_decrypt_attempt(generation, decoded_pn, decrypt_result)
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

    pub fn invalidate(&self) -> Option<(HeaderProtectionKeys, ArcOneRttPacketKeys)> {
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

    pub fn remote_keys(&self) -> Option<(Arc<dyn HeaderProtectionKey>, ArcOneRttPacketKeys)> {
        match &mut *self.lock_guard() {
            OneRttKeysState::Ready { hpk, pk, .. } => Some((hpk.remote.clone(), pk.clone())),
            _ => None,
        }
    }

    /// Asynchronously obtain the remote keys for removing header protection and packet decryption.
    ///
    /// Returns [`GetRemoteKeys`], which implements the Future trait.
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

#[cfg(test)]
mod tests {
    use rustls::{Error as RustlsError, quic::Tag};

    use super::*;

    struct DummyPacketKey;

    impl HeaderProtectionKey for DummyPacketKey {
        fn encrypt_in_place(
            &self,
            _sample: &[u8],
            _first_byte: &mut u8,
            _packet_number: &mut [u8],
        ) -> Result<(), RustlsError> {
            Err(RustlsError::General("dummy key".into()))
        }

        fn decrypt_in_place(
            &self,
            _sample: &[u8],
            _first_byte: &mut u8,
            _packet_number: &mut [u8],
        ) -> Result<(), RustlsError> {
            Err(RustlsError::General("dummy key".into()))
        }

        fn sample_len(&self) -> usize {
            16
        }
    }

    impl PacketKey for DummyPacketKey {
        fn encrypt_in_place(
            &self,
            _packet_number: u64,
            _header: &[u8],
            _payload: &mut [u8],
        ) -> Result<Tag, RustlsError> {
            Err(RustlsError::General("dummy key".into()))
        }

        fn decrypt_in_place<'a>(
            &self,
            _packet_number: u64,
            _header: &[u8],
            _payload: &'a mut [u8],
        ) -> Result<&'a [u8], RustlsError> {
            Err(RustlsError::General("dummy key".into()))
        }

        fn tag_len(&self) -> usize {
            16
        }

        fn confidentiality_limit(&self) -> u64 {
            u64::MAX
        }

        fn integrity_limit(&self) -> u64 {
            u64::MAX
        }
    }

    fn dummy_pk() -> Arc<dyn PacketKey> {
        Arc::new(DummyPacketKey)
    }

    fn test_keys_with_entries(entries: VecDeque<KeyEntry>) -> OneRttPacketKeys {
        OneRttPacketKeys {
            counter: entries.back().map(|e| e.generation).unwrap_or(0),
            keys: entries,
            secrets: None,
            cur_phase: KeyPhaseBit::Zero,
            sent_pn_ranges: HashMap::new(),
            largest_acked_pn: None,
            sent_pn_stage: HashMap::new(),
            outstanding_pn_count: HashMap::new(),
            contiguous_decrypt_failures: 0,
        }
    }

    #[test]
    fn key_update_error_on_consecutive_peer_updates_before_confirming_first() {
        let mut entries = VecDeque::new();
        let mut e0 = KeyEntry::new(0, dummy_pk(), dummy_pk());
        e0.rcvd_pn_range = Some(1..11);
        entries.push_back(e0);

        let mut e1 = KeyEntry::new(1, dummy_pk(), dummy_pk());
        e1.rcvd_pn_range = None;
        entries.push_back(e1);

        let mut keys = test_keys_with_entries(entries);
        let err = keys
            .update_by_peer()
            .expect_err("must reject detect consecutive peer key update");
        assert_eq!(err.kind(), ErrorKind::KeyUpdate);
    }

    #[test]
    fn key_update_error_on_peer_unsynced_ack_using_old_key_phase() {
        let mut entries = VecDeque::new();
        entries.push_back(KeyEntry::new(0, dummy_pk(), dummy_pk()));
        entries.push_back(KeyEntry::new(1, dummy_pk(), dummy_pk()));
        let mut keys = test_keys_with_entries(entries);

        keys.sent_pn_stage.insert(42, 1);

        let err = keys
            .apply_packet_acked(42, 42, Some(0))
            .expect_err("must reject old-key ACKing new-key packet");
        assert_eq!(err.kind(), ErrorKind::KeyUpdate);
    }

    #[test]
    fn key_update_error_on_key_downgrade_high_pn_decrypted_with_old_key() {
        let mut entries = VecDeque::new();
        let mut e0 = KeyEntry::new(0, dummy_pk(), dummy_pk());
        e0.rcvd_pn_range = Some(1..51);
        entries.push_back(e0);

        let mut e1 = KeyEntry::new(1, dummy_pk(), dummy_pk());
        e1.rcvd_pn_range = Some(100..121);
        entries.push_back(e1);

        let mut keys = test_keys_with_entries(entries);
        let err = keys
            .on_packet_decrypted(130, 0)
            .expect_err("must reject decrypting higher PN with old key");
        assert_eq!(err.kind(), ErrorKind::KeyUpdate);
    }

    #[test]
    fn normal_key_update_flow() {
        let mut entries = VecDeque::new();
        entries.push_back(KeyEntry::new(0, dummy_pk(), dummy_pk()));

        let mut keys = test_keys_with_entries(entries);

        // Check initial state
        let (generation, phase, _key) = keys.get_local_key();
        assert_eq!(generation, 0);
        assert_eq!(phase, KeyPhaseBit::Zero);

        // Set acknowledged packet numbers to make key update ready
        keys.sent_pn_ranges.insert(0, 0..10);
        keys.largest_acked_pn = Some(5);

        // Note: Since rotate_to_next_key_generation() requires secrets,
        // this test mainly verifies the preparation conditions for key update,
        // not the actual key rotation
        // Verify key update readiness status
        let is_ready = keys.is_send_key_update_ready();
        assert!(is_ready);

        // Verify key selection logic
        let candidates = keys.candidate_generations(KeyPhaseBit::Zero);
        assert_eq!(candidates, [Some(0), None]);
    }

    #[test]
    fn key_generation_boundary_management() {
        let mut entries = VecDeque::new();

        // Create 4 generations of keys to test window management
        for i in 0..4 {
            entries.push_back(KeyEntry::new(i, dummy_pk(), dummy_pk()));
        }

        let mut keys = test_keys_with_entries(entries);
        keys.counter = 3;

        // Note: Since rotate_to_next_key_generation() requires secrets,
        // this test mainly verifies the key generation boundary management logic
        // Verify initial state
        assert_eq!(keys.keys.len(), 4);
        assert_eq!(keys.keys.front().unwrap().generation, 0);
        assert_eq!(keys.keys.back().unwrap().generation, 3);

        // Test candidate generation selection logic
        let candidates = keys.candidate_generations(KeyPhaseBit::Zero);
        assert_eq!(candidates, [Some(3), Some(1)]);

        // Verify key generation boundary management (manually simulate window management)
        while keys.keys.len() > 3 {
            keys.keys.pop_front();
        }
        assert_eq!(keys.keys.len(), 3);
        assert_eq!(keys.keys.front().unwrap().generation, 1);
        assert_eq!(keys.keys.back().unwrap().generation, 3);
    }

    #[test]
    fn packet_number_ordering_and_range_management() {
        let mut entries = VecDeque::new();
        entries.push_back(KeyEntry::new(0, dummy_pk(), dummy_pk()));

        let mut keys = test_keys_with_entries(entries);

        // Track sent packets
        keys.track_packet_sent(0, 10);
        keys.track_packet_sent(0, 20);
        keys.track_packet_sent(0, 15);

        // Verify packet number range
        let range = keys.sent_pn_ranges.get(&0).unwrap();
        assert_eq!(range.start, 10);
        assert_eq!(range.end, 21); // Packets 10, 15, 20 -> range 10..21

        // Verify packet number to generation mapping
        assert_eq!(keys.sent_pn_stage.get(&10), Some(&0));
        assert_eq!(keys.sent_pn_stage.get(&15), Some(&0));
        assert_eq!(keys.sent_pn_stage.get(&20), Some(&0));
    }

    #[test]
    fn successful_decryption_flow() {
        let mut entries = VecDeque::new();
        entries.push_back(KeyEntry::new(0, dummy_pk(), dummy_pk()));

        let mut keys = test_keys_with_entries(entries);

        // Successfully decrypt packet
        let result = keys.apply_decrypt_attempt(0, 5, Ok(100));
        assert!(matches!(result, Ok(DecryptAttemptResult::Success(100))));

        // Verify packet number range has been updated
        let entry = keys.keys.front().unwrap();
        assert_eq!(entry.rcvd_pn_range, Some(5..6));

        // Consecutive decryption failure counter should be reset
        assert_eq!(keys.contiguous_decrypt_failures, 0);
    }

    #[test]
    fn candidate_key_selection_logic() {
        let mut entries = VecDeque::new();

        // Create multiple generations of keys
        for i in 0..3 {
            let mut entry = KeyEntry::new(i, dummy_pk(), dummy_pk());
            if i == 0 {
                entry.rcvd_pn_range = Some(1..11);
            }
            entries.push_back(entry);
        }

        let keys = test_keys_with_entries(entries);

        // Test selection when packet number is within range
        let (candidates, next_gen) = keys.collect_decrypt_key_candidates(5, KeyPhaseBit::Zero);
        assert_eq!(candidates.len(), 1); // Should only select one candidate
        assert_eq!(candidates[0].0, 0); // Should select generation 0
        assert!(next_gen.is_none());

        // Test selection when packet number is outside range
        let (candidates, next_gen) = keys.collect_decrypt_key_candidates(20, KeyPhaseBit::Zero);
        assert_eq!(candidates.len(), 2); // Should select two candidates
        assert!(next_gen.is_none());
    }

    #[test]
    fn key_phase_bit_management() {
        let mut entries = VecDeque::new();
        entries.push_back(KeyEntry::new(0, dummy_pk(), dummy_pk()));

        let mut keys = test_keys_with_entries(entries);

        // Initial phase
        assert_eq!(keys.cur_phase, KeyPhaseBit::Zero);

        // Test candidate generation selection
        let candidates = keys.candidate_generations(KeyPhaseBit::Zero);
        assert_eq!(candidates, [Some(0), None]); // Current generation and generation-2

        // Switch phase
        keys.cur_phase = KeyPhaseBit::One;
        let candidates = keys.candidate_generations(KeyPhaseBit::Zero);
        assert_eq!(candidates, [None, Some(1)]); // Generation-1 and generation+1
    }

    #[test]
    fn decryption_failure_handling() {
        let mut entries = VecDeque::new();
        entries.push_back(KeyEntry::new(0, dummy_pk(), dummy_pk()));

        let mut keys = test_keys_with_entries(entries);

        // Test consecutive decryption failures
        for i in 0..3 {
            let result = keys.apply_decrypt_attempt(0, i, Err(()));
            assert!(matches!(result, Ok(DecryptAttemptResult::ContinueTrying)));
            assert_eq!(keys.contiguous_decrypt_failures, i as u32 + 1);
        }

        // The 4th failure should give up
        let result = keys.apply_decrypt_attempt(0, 3, Err(()));
        assert!(matches!(result, Ok(DecryptAttemptResult::GiveUp)));
    }

    #[test]
    fn arc_keys_concurrent_access_safety() {
        use std::{sync::Arc, thread};

        let keys = ArcKeys::new_pending();
        let keys_clone = keys.clone();

        // Set keys in another thread
        let handle = thread::spawn(move || {
            let header_key = Arc::new(DummyPacketKey) as Arc<dyn HeaderProtectionKey>;
            let packet_key = dummy_pk();
            keys_clone.set_keys(Keys {
                local: DirectionalKeys {
                    header: header_key.clone(),
                    packet: packet_key.clone(),
                },
                remote: DirectionalKeys {
                    header: header_key,
                    packet: packet_key,
                },
            });
        });

        handle.join().unwrap();

        // Verify keys have been properly set
        let local_keys = keys.get_local_keys();
        assert!(local_keys.is_some());
    }

    #[test]
    fn arc_one_rtt_keys_integration() {
        let keys = ArcOneRttKeys::new_pending();

        // Verify initial state
        let local_keys = keys.get_local_keys();
        assert!(local_keys.is_none());

        // Test key invalidation
        let invalidated = keys.invalidate();
        assert!(invalidated.is_none());

        // Verify state after invalidation
        let local_keys = keys.get_local_keys();
        assert!(local_keys.is_none());
    }

    #[test]
    fn keys_state_lifecycle() {
        // Test Pending -> Ready transition
        let mut state: KeysState<String> = KeysState::Pending(None);
        assert!(state.get().is_none());

        state.set("test".to_string());
        assert_eq!(state.get(), Some(&"test".to_string()));

        // Test Invalid transition
        let retrieved = state.invalid();
        assert_eq!(retrieved, Some("test".to_string()));
        assert!(state.get().is_none());

        // Test Ready -> Invalid transition
        let mut state: KeysState<String> = KeysState::Ready("ready".to_string());
        let retrieved = state.invalid();
        assert_eq!(retrieved, Some("ready".to_string()));
        assert!(state.get().is_none());
    }

    #[test]
    fn keys_state_waker_behavior() {
        let mut state: KeysState<String> = KeysState::Pending(None);

        // Setting keys should work even without waker
        state.set("test".to_string());
        assert!(state.get().is_some());

        // Invalid state should still work
        state.invalid();
        assert!(state.get().is_none());
    }

    #[test]
    fn directional_keys_conversion() {
        let header_key = Arc::new(DummyPacketKey) as Arc<dyn HeaderProtectionKey>;
        let packet_key = dummy_pk();

        let dir_keys = DirectionalKeys {
            header: header_key.clone(),
            packet: packet_key.clone(),
        };

        assert_eq!(dir_keys.header.sample_len(), 16);
        assert_eq!(dir_keys.packet.tag_len(), 16);
    }

    #[test]
    fn keys_conversion() {
        let header_key = Arc::new(DummyPacketKey) as Arc<dyn HeaderProtectionKey>;
        let packet_key = dummy_pk();

        let keys = Keys {
            local: DirectionalKeys {
                header: header_key.clone(),
                packet: packet_key.clone(),
            },
            remote: DirectionalKeys {
                header: header_key.clone(),
                packet: packet_key.clone(),
            },
        };

        assert_eq!(keys.local.header.sample_len(), 16);
        assert_eq!(keys.remote.packet.tag_len(), 16);
    }

    #[test]
    fn key_entry_update_rcvd_pn() {
        let local_key = dummy_pk();
        let remote_key = dummy_pk();
        let mut entry = KeyEntry::new(0, local_key, remote_key);

        assert!(entry.rcvd_pn_range.is_none());

        entry.update_rcvd_pn(5);
        assert_eq!(entry.rcvd_pn_range, Some(5..6));

        entry.update_rcvd_pn(3);
        assert_eq!(entry.rcvd_pn_range, Some(3..6));

        entry.update_rcvd_pn(10);
        assert_eq!(entry.rcvd_pn_range, Some(3..11));
    }

    #[test]
    fn get_key_error_variants() {
        // Test GetKeyError variants are comparable
        assert_eq!(GetKeyError::Retired, GetKeyError::Retired);
        assert_eq!(GetKeyError::Unknown, GetKeyError::Unknown);
        assert_ne!(GetKeyError::Retired, GetKeyError::Unknown);
    }

    #[test]
    fn decrypt_attempt_result_variants() {
        assert_eq!(
            DecryptAttemptResult::Success(100),
            DecryptAttemptResult::Success(100)
        );
        assert_eq!(
            DecryptAttemptResult::ContinueTrying,
            DecryptAttemptResult::ContinueTrying
        );
        assert_eq!(DecryptAttemptResult::GiveUp, DecryptAttemptResult::GiveUp);
        assert_ne!(
            DecryptAttemptResult::Success(100),
            DecryptAttemptResult::Success(200)
        );
    }

    #[test]
    fn key_entry_basic_properties() {
        let local_key = dummy_pk();
        let remote_key = dummy_pk();
        let entry = KeyEntry::new(5, local_key, remote_key);

        assert_eq!(entry.generation, 5);
        assert_eq!(entry.local_key.tag_len(), 16);
        assert_eq!(entry.remote_key.tag_len(), 16);
        assert!(entry.rcvd_pn_range.is_none());
    }
}
