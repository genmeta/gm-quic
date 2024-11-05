use bytes::{buf::UninitSlice, BufMut, BytesMut};
use deref_derive::{Deref, DerefMut};
use encrypt::{encode_long_first_byte, encode_short_first_byte, encrypt_packet, protect_header};
use enum_dispatch::enum_dispatch;
use header::io::WriteHeader;

use crate::{
    cid::ConnectionId,
    frame::{
        io::{WriteDataFrame, WriteFrame},
        BeFrame, ContainSpec, Spec,
    },
    util::DescribeData,
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
///               +---> packet number length    +---> actual encoded packet number
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

pub struct PacketWriter<'b> {
    buffer: &'b mut [u8],
    hdr_len: usize,
    len_encoding: usize,
    pn: (u64, PacketNumber),
    cursor: usize,
    end: usize,
    tag_len: usize,

    // Packets containing only frames with [`Spec::N`] are not ack-eliciting;
    // otherwise, they are ack-eliciting.
    ack_eliciting: bool,
    // A Boolean that indicates whether the packet counts toward bytes in flight.
    // See [Section 2](https://www.rfc-editor.org/rfc/rfc9002#section-2)
    // and [Appendix A.1](https://www.rfc-editor.org/rfc/rfc9002#section-a.1)
    // of [QUIC Recovery](https://www.rfc-editor.org/rfc/rfc9002).
    //
    // Packets containing only frames with [`Spec::C`] do not
    // count toward bytes in flight for congestion control purposes.
    in_flight: bool,
    // Packets containing only frames with [`Spec::P`] can be used to
    // probe new network paths during connection migration.
    _probe_new_path: bool,
}

impl<'b> PacketWriter<'b> {
    pub fn new<H>(
        header: &H,
        buffer: &'b mut [u8],
        pn: (u64, PacketNumber),
        tag_len: usize,
    ) -> Option<Self>
    where
        H: EncodeHeader,
        for<'a> &'a mut [u8]: WriteHeader<H>,
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

        let end = buffer.len() - tag_len;
        Some(Self {
            buffer,
            hdr_len,
            len_encoding,
            pn,
            cursor: hdr_len + len_encoding + encoded_pn.size(),
            end,
            tag_len,
            ack_eliciting: false,
            in_flight: false,
            _probe_new_path: false,
        })
    }

    pub fn pad(&mut self, cnt: usize) {
        self.put_bytes(0, cnt);
    }

    pub fn write_frame<F>(&mut self, frame: &F)
    where
        F: BeFrame,
        Self: WriteFrame<F>,
    {
        let specs = frame.frame_type().specs();
        self.ack_eliciting |= !specs.contain(Spec::N);
        self.in_flight |= !specs.contain(Spec::C);

        self.put_frame(frame);
    }

    pub fn write_data_frame<F, D>(&mut self, frame: &F, data: &D)
    where
        F: BeFrame,
        D: DescribeData,
        Self: WriteDataFrame<F, D>,
    {
        self.ack_eliciting = true;
        self.in_flight = true;
        self.put_data_frame(frame, data);
    }

    #[inline]
    pub fn is_ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }

    #[inline]
    pub fn in_flight(&self) -> bool {
        self.in_flight
    }

    pub fn encrypt_long_packet(
        &mut self,
        hpk: &dyn rustls::quic::HeaderProtectionKey,
        pk: &dyn rustls::quic::PacketKey,
    ) -> usize {
        let (actual_pn, encoded_pn) = self.pn;
        encode_long_first_byte(&mut self.buffer[0], encoded_pn.size());

        let pkt_size = self.cursor + self.tag_len;
        let payload_len = pkt_size - self.hdr_len - self.len_encoding;
        let mut pn_buf = &mut self.buffer[self.hdr_len..self.hdr_len + self.len_encoding];
        pn_buf.encode_varint(&VarInt::try_from(payload_len).unwrap(), EncodeBytes::Two);

        encrypt_packet(
            pk,
            actual_pn,
            &mut self.buffer[..pkt_size],
            self.hdr_len + self.len_encoding + encoded_pn.size(),
        );
        protect_header(
            hpk,
            &mut self.buffer[..pkt_size],
            self.hdr_len,
            encoded_pn.size(),
        );
        pkt_size
    }

    pub fn encrypt_short_packet(
        &mut self,
        key_phase: KeyPhaseBit,
        hpk: &dyn rustls::quic::HeaderProtectionKey,
        pk: &dyn rustls::quic::PacketKey,
    ) -> usize {
        let (actual_pn, encoded_pn) = self.pn;
        encode_short_first_byte(&mut self.buffer[0], encoded_pn.size(), key_phase);

        let pkt_size = self.cursor + self.tag_len;
        encrypt_packet(
            pk,
            actual_pn,
            &mut self.buffer[..pkt_size],
            self.hdr_len + self.len_encoding + encoded_pn.size(),
        );
        protect_header(
            hpk,
            &mut self.buffer[..pkt_size],
            self.hdr_len,
            encoded_pn.size(),
        );
        pkt_size
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
        UninitSlice::new(&mut self.buffer[self.cursor..self.end])
    }
}
