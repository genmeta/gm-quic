use std::sync::Arc;

use bytes::{buf::UninitSlice, BufMut, BytesMut};
use deref_derive::{Deref, DerefMut};
use encrypt::{encode_long_first_byte, encode_short_first_byte, encrypt_packet, protect_header};
use enum_dispatch::enum_dispatch;
use getset::CopyGetters;
use header::{io::WriteHeader, LongHeader};

use crate::{
    cid::ConnectionId,
    frame::{
        io::{WriteDataFrame, WriteFrame},
        BeFrame, ContainSpec, Spec,
    },
    util::{DescribeData, WriteData},
    varint::{EncodeBytes, VarInt, WriteVarInt},
};

/// QUIC packet parse error definitions.
pub mod error;

/// Define signal util, such as key phase bit and spin bit.
pub mod signal;
#[doc(hidden)]
pub use signal::{KeyPhaseBit, SpinBit};

/// Definitions of QUIC packet types.
pub mod r#type;
#[doc(hidden)]
pub use r#type::{
    GetPacketNumberLength, LongSpecificBits, ShortSpecificBits, Type, LONG_RESERVED_MASK,
    SHORT_RESERVED_MASK,
};

/// Definitions of QUIC packet headers.
pub mod header;
#[doc(hidden)]
pub use header::{
    long, EncodeHeader, GetDcid, GetType, HandshakeHeader, Header, InitialHeader,
    LongHeaderBuilder, OneRttHeader, RetryHeader, VersionNegotiationHeader, ZeroRttHeader,
};

/// The io module provides the functions to parse the QUIC packet.
///
/// The writing of the QUIC packet is not provided here, they are written in place.
pub mod io;

/// Encoding and decoding of packet number
pub mod number;
#[doc(hidden)]
pub use number::{take_pn_len, PacketNumber, WritePacketNumber};

/// Include operations such as decrypting QUIC packets, removing header protection,
/// and parsing the first byte of the packet to get the right packet numbers
pub mod decrypt;

/// Include operations such as encrypting QUIC packets, adding header protection,
/// and encoding the first byte of the packet with pn_len and key_phase optionally.
pub mod encrypt;

/// Encapsulate the crypto keys's logic for long headers and 1-RTT headers.
pub mod keys;

/// The sum type of all QUIC packet headers.
#[derive(Debug, Clone)]
#[enum_dispatch(GetDcid, GetType)]
pub enum DataHeader {
    Long(long::DataHeader),
    Short(OneRttHeader),
}

/// The sum type of all QUIC data packets.
///
/// The long header has the len field, the short header does not have the len field.
/// Remember, the len field is not an attribute of the header, but a attribute of the packet.
///
/// ```text
///                                 +---> payload length in long packet
///                                 |     |<----------- payload --------->|
/// +-----------+---+--------+------+-----+-----------+---......--+-------+
/// |X|1|X X 0 0|0 0| ...hdr | len(0..16) | pn(8..32) | body...   |  tag  |
/// +---+-------+-+-+--------+------------+-----+-----+---......--+-------+
///               |                             |
///               +---> encoded pn length       +---> encoded packet number
/// ```
#[derive(Debug, Clone, Deref, DerefMut)]
pub struct DataPacket {
    #[deref]
    pub header: DataHeader,
    pub bytes: BytesMut,
    // payload_offset
    pub offset: usize,
}

impl GetType for DataPacket {
    fn get_type(&self) -> Type {
        self.header.get_type()
    }
}

/// The sum type of all QUIC packets.
#[derive(Debug, Clone)]
pub enum Packet {
    VN(VersionNegotiationHeader),
    Retry(RetryHeader),
    // Data(header, bytes, payload_offset)
    Data(DataPacket),
}

/// QUIC packet reader, reading packets from the incoming datagrams.
///
/// The parsing here does not involve removing header protection or decrypting the packet.
/// It only parses information such as packet type and connection ID,
/// and prepares for further delivery to the connection by finding the connection ID.
///
/// The received packet is a BytesMut, in order to be decrypted in future, and make as few
/// copies cheaply until it is read by the application layer.
#[derive(Debug)]
pub struct PacketReader {
    raw: BytesMut,
    dcid_len: usize,
    // TODO: 添加level，各种包类型顺序不能错乱，否则失败
}

impl PacketReader {
    pub fn new(raw: BytesMut, dcid_len: usize) -> Self {
        Self { raw, dcid_len }
    }
}

impl Iterator for PacketReader {
    type Item = Result<Packet, error::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }

        match io::be_packet(&mut self.raw, self.dcid_len) {
            Ok(packet) => Some(Ok(packet)),
            Err(e) => {
                self.raw.clear(); // no longer parsing
                Some(Err(e))
            }
        }
    }
}

/// During the formation of a packet, various frames are arranged into the packet.
pub trait MarshalFrame<F> {
    fn dump_frame(&mut self, frame: F) -> Option<F>;
}

pub trait MarshalDataFrame<F, D> {
    fn dump_frame_with_data(&mut self, frame: F, data: D) -> Option<F>;
}

/// Mainly customized for PathChallengeFrame and PathResponseFrame.
/// These frames are sent in the data space but do not need to be
/// reliably guaranteed in the data space.
pub trait MarshalPathFrame<F> {
    fn dump_path_frame(&mut self, frame: F);
}

enum Keys {
    LongHeaderPacket {
        keys: Arc<rustls::quic::Keys>,
    },
    ShortHeaderPacket {
        hpk: Arc<dyn rustls::quic::HeaderProtectionKey>,
        pk: Arc<dyn rustls::quic::PacketKey>,
        key_phase: KeyPhaseBit,
    },
}

impl Keys {
    fn hpk(&self) -> &dyn rustls::quic::HeaderProtectionKey {
        match self {
            Self::LongHeaderPacket { keys } => keys.local.header.as_ref(),
            Self::ShortHeaderPacket { hpk, .. } => hpk.as_ref(),
        }
    }

    fn pk(&self) -> &dyn rustls::quic::PacketKey {
        match self {
            Self::LongHeaderPacket { keys } => keys.local.packet.as_ref(),
            Self::ShortHeaderPacket { pk, .. } => pk.as_ref(),
        }
    }

    fn key_phase(&self) -> Option<KeyPhaseBit> {
        match self {
            Self::LongHeaderPacket { .. } => None,
            Self::ShortHeaderPacket { key_phase, .. } => Some(*key_phase),
        }
    }
}

#[derive(CopyGetters)]
pub struct MiddleAssembledPacket {
    hdr_len: usize,
    len_encoding: usize,
    pn: (u64, PacketNumber),

    cursor: usize,
    end: usize,

    // keys, can also be used to indicates whether the packet is long header or short header
    keys: Keys,

    // Packets containing only frames with [`Spec::N`] are not ack-eliciting;
    // otherwise, they are ack-eliciting.
    #[getset(get_copy = "pub")]
    ack_eliciting: bool,
    // A Boolean that indicates whether the packet counts toward bytes in flight.
    // See [Section 2](https://www.rfc-editor.org/rfc/rfc9002#section-2)
    // and [Appendix A.1](https://www.rfc-editor.org/rfc/rfc9002#section-a.1)
    // of [QUIC Recovery](https://www.rfc-editor.org/rfc/rfc9002).
    //
    // Packets containing only frames with [`Spec::C`] do not
    // count toward bytes in flight for congestion control purposes.
    #[getset(get_copy = "pub")]
    in_flight: bool,
    // Packets containing only frames with [`Spec::P`] can be used to
    // probe new network paths during connection migration.
    _probe_new_path: bool,
}

impl MiddleAssembledPacket {
    pub fn resume(mut self, buffer: &mut [u8]) -> PacketWriter {
        self.end = buffer.len() - self.keys.pk().tag_len();
        assert!(self.end >= self.cursor);
        PacketWriter {
            packet: self,
            buffer,
        }
    }

    pub fn size(&self) -> usize {
        let payload_len = self.cursor - self.hdr_len - self.len_encoding;
        let pkt_size = (payload_len + self.keys.pk().tag_len()).max(20);
        self.hdr_len + self.len_encoding + pkt_size
    }

    fn is_short_header(&self) -> bool {
        self.keys.key_phase().is_some()
    }
}

#[derive(Deref, DerefMut)]
pub struct PacketWriter<'b> {
    #[deref]
    packet: MiddleAssembledPacket,
    buffer: &'b mut [u8],
}

impl<'b> PacketWriter<'b> {
    pub fn new_long<S>(
        header: &LongHeader<S>,
        buffer: &'b mut [u8],
        pn: (u64, PacketNumber),
        keys: Arc<rustls::quic::Keys>,
    ) -> Option<Self>
    where
        S: EncodeHeader,
        for<'a> &'a mut [u8]: WriteHeader<LongHeader<S>>,
    {
        let hdr_len = header.size();
        let len_encoding = header.length_encoding();
        if buffer.len() < hdr_len + len_encoding + 20 {
            return None;
        }

        let (mut hdr_buf, mut payload_buf) = buffer.split_at_mut(hdr_len + len_encoding);
        let encoded_pn = pn.1;
        hdr_buf.put_header(header);
        payload_buf.put_packet_number(encoded_pn);

        let cursor = hdr_len + len_encoding + encoded_pn.size();
        let keys = Keys::LongHeaderPacket { keys };
        let end = buffer.len() - keys.pk().tag_len();
        let packet = MiddleAssembledPacket {
            hdr_len,
            len_encoding,
            pn,
            cursor,
            end,
            keys,
            ack_eliciting: false,
            in_flight: false,
            _probe_new_path: false,
        };
        Some(Self { buffer, packet })
    }

    pub fn new_short(
        header: &OneRttHeader,
        buffer: &'b mut [u8],
        pn: (u64, PacketNumber),
        hpk: Arc<dyn rustls::quic::HeaderProtectionKey>,
        pk: Arc<dyn rustls::quic::PacketKey>,
        key_phase: KeyPhaseBit,
    ) -> Option<Self> {
        let hdr_len = header.size();
        if buffer.len() < hdr_len + 20 {
            return None;
        }

        let (mut hdr_buf, mut payload_buf) = buffer.split_at_mut(hdr_len);
        let encoded_pn = pn.1;
        hdr_buf.put_header(header);
        payload_buf.put_packet_number(encoded_pn);
        let cursor = hdr_len + encoded_pn.size();
        let keys = Keys::ShortHeaderPacket { hpk, pk, key_phase };
        let end = buffer.len() - keys.pk().tag_len();
        let packet = MiddleAssembledPacket {
            hdr_len,
            len_encoding: 0,
            pn,
            cursor,
            end,
            keys,
            ack_eliciting: false,
            in_flight: false,
            _probe_new_path: false,
        };
        Some(Self { buffer, packet })
    }

    pub fn abandon(self) -> MiddleAssembledPacket {
        self.packet
    }

    pub fn pad(&mut self, cnt: usize) {
        self.put_bytes(0, cnt);
    }

    #[inline]
    pub fn is_ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }

    #[inline]
    pub fn in_flight(&self) -> bool {
        self.in_flight
    }

    pub fn is_empty(&self) -> bool {
        self.cursor == self.hdr_len + self.len_encoding + self.pn.1.size()
    }

    pub fn encrypt_and_protect(&mut self) -> AssembledPacket {
        let payload_len = self.cursor - self.hdr_len - self.len_encoding;

        let tag_len = self.keys.pk().tag_len();
        debug_assert!(payload_len > 0);
        if payload_len + tag_len < 20 {
            let padding_len = 20 - payload_len - tag_len;
            self.pad(padding_len);
        }

        let (actual_pn, encoded_pn) = self.pn;
        let pn_len = encoded_pn.size();
        let pkt_size = self.cursor + tag_len;

        if self.is_short_header() {
            let key_phase = self.keys.key_phase().unwrap();
            encode_short_first_byte(&mut self.buffer[0], pn_len, key_phase);

            let pk = self.packet.keys.pk();
            let payload_offset = self.hdr_len;
            let body_offset = payload_offset + pn_len;
            encrypt_packet(pk, actual_pn, &mut self.buffer[..pkt_size], body_offset);

            let hpk = self.packet.keys.hpk();
            protect_header(hpk, &mut self.buffer[..pkt_size], payload_offset, pn_len);
        } else {
            let packet_len = payload_len + tag_len;
            let len_buffer_range = self.hdr_len..self.hdr_len + self.len_encoding;
            let mut len_buf = &mut self.buffer[len_buffer_range];
            len_buf.encode_varint(&VarInt::try_from(packet_len).unwrap(), EncodeBytes::Two);

            encode_long_first_byte(&mut self.buffer[0], pn_len);

            let pk = self.packet.keys.pk();
            let payload_offset = self.hdr_len + self.len_encoding;
            let body_offset = payload_offset + pn_len;
            encrypt_packet(pk, actual_pn, &mut self.buffer[..pkt_size], body_offset);

            let hpk = self.packet.keys.hpk();
            protect_header(hpk, &mut self.buffer[..pkt_size], payload_offset, pn_len);
        }
        AssembledPacket {
            pn: actual_pn,
            size: pkt_size,
            is_ack_eliciting: self.ack_eliciting,
            in_flight: self.in_flight,
        }
    }
}

#[derive(Debug, CopyGetters, Clone, Copy)]
pub struct AssembledPacket {
    #[getset(get_copy = "pub")]
    pn: u64,
    #[getset(get_copy = "pub")]
    size: usize,
    #[getset(get_copy = "pub")]
    is_ack_eliciting: bool,
    #[getset(get_copy = "pub")]
    in_flight: bool,
}

impl<F> MarshalFrame<F> for PacketWriter<'_>
where
    F: BeFrame,
    Self: WriteFrame<F>,
{
    fn dump_frame(&mut self, frame: F) -> Option<F> {
        let specs = frame.frame_type().specs();
        self.ack_eliciting |= !specs.contain(Spec::NonAckEliciting);
        self.in_flight |= !specs.contain(Spec::CongestionControlFree);

        self.put_frame(&frame);
        Some(frame)
    }
}

impl<F, D> MarshalDataFrame<F, D> for PacketWriter<'_>
where
    F: BeFrame,
    D: DescribeData,
    Self: WriteData<D> + WriteDataFrame<F, D>,
{
    fn dump_frame_with_data(&mut self, frame: F, data: D) -> Option<F> {
        self.ack_eliciting = true;
        self.in_flight = true;
        self.put_data_frame(&frame, &data);
        Some(frame)
    }
}

unsafe impl BufMut for PacketWriter<'_> {
    fn remaining_mut(&self) -> usize {
        self.end - self.cursor
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        if self.remaining_mut() < cnt {
            panic!(
                "advance out of bounds: the len is {} but advancing by {}",
                cnt,
                self.remaining_mut()
            );
        }

        self.cursor += cnt;
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let range = self.cursor..self.end;
        UninitSlice::new(&mut self.buffer[range])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::CryptoFrame;

    struct TransparentKeys;

    impl rustls::quic::PacketKey for TransparentKeys {
        fn decrypt_in_place<'a>(
            &self,
            _packet_number: u64,
            _header: &[u8],
            payload: &'a mut [u8],
        ) -> Result<&'a [u8], rustls::Error> {
            Ok(&payload[..payload.len() - self.tag_len()])
        }

        fn encrypt_in_place(
            &self,
            _packet_number: u64,
            _header: &[u8],
            _payload: &mut [u8],
        ) -> Result<rustls::quic::Tag, rustls::Error> {
            Ok(rustls::quic::Tag::from("transparent_keys".as_bytes()))
        }

        fn confidentiality_limit(&self) -> u64 {
            0
        }

        fn integrity_limit(&self) -> u64 {
            0
        }

        fn tag_len(&self) -> usize {
            16
        }
    }

    impl rustls::quic::HeaderProtectionKey for TransparentKeys {
        fn decrypt_in_place(
            &self,
            _sample: &[u8],
            _first_byte: &mut u8,
            _payload: &mut [u8],
        ) -> Result<(), rustls::Error> {
            Ok(())
        }

        fn encrypt_in_place(
            &self,
            _sample: &[u8],
            _first_byte: &mut u8,
            _payload: &mut [u8],
        ) -> Result<(), rustls::Error> {
            Ok(())
        }

        fn sample_len(&self) -> usize {
            20
        }
    }

    #[test]
    fn test_initial_packet_writer() {
        let mut buffer = vec![0u8; 128];
        let header = LongHeaderBuilder::with_cid(
            ConnectionId::from_slice("testdcid".as_bytes()),
            ConnectionId::from_slice("testscid".as_bytes()),
        )
        .initial(b"test_token".to_vec());

        let pn = (0, PacketNumber::encode(0, 0));

        let keys = Arc::new(rustls::quic::Keys {
            local: rustls::quic::DirectionalKeys {
                packet: Box::new(TransparentKeys),
                header: Box::new(TransparentKeys),
            },
            remote: rustls::quic::DirectionalKeys {
                packet: Box::new(TransparentKeys),
                header: Box::new(TransparentKeys),
            },
        });

        let mut writer = PacketWriter::new_long(&header, &mut buffer, pn, keys).unwrap();
        let frame = CryptoFrame {
            length: VarInt::from_u32(12),
            offset: VarInt::from_u32(0),
        };
        writer.dump_frame_with_data(frame, "client_hello".as_bytes());

        assert!(writer.is_ack_eliciting());
        assert!(writer.in_flight());

        let packet = writer.encrypt_and_protect();
        assert!(packet.is_ack_eliciting());
        assert!(packet.in_flight());
        assert_eq!(packet.size(), 68);
        assert_eq!(
            &buffer[..packet.size()],
            [
                // initial packet:
                // header form (1) = 1,, long header
                // fixed bit (1) = 1,
                // long packet type (2) = 0, initial packet
                // reserved bits (2) = 0,
                // packet number length (2) = 0, 1 byte
                192, // first byte
                0, 0, 0, 1, // quic version
                // destination connection id, "testdcid"
                8, // dcid length
                b't', b'e', b's', b't', b'd', b'c', b'i', b'd', // dcid bytes
                // source connection id, "testscid"
                8, // scid length
                b't', b'e', b's', b't', b's', b'c', b'i', b'd', // scid bytes
                10,   // token length, no token
                b't', b'e', b's', b't', b'_', b't', b'o', b'k', b'e', b'n', // token bytes
                64, 32, // payload length, 2 bytes encoded varint
                0,  // encoded packet number
                // crypto frame header
                6,  // crypto frame type
                0,  // crypto frame offset
                12, // crypto frame length
                // crypto frame data, "client hello"
                b'c', b'l', b'i', b'e', b'n', b't', b'_', b'h', b'e', b'l', b'l', b'o',
                // tag, "transparent_keys"
                b't', b'r', b'a', b'n', b's', b'p', b'a', b'r', b'e', b'n', b't', b'_', b'k', b'e',
                b'y', b's',
            ]
            .as_slice()
        );
    }
}
