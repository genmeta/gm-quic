use std::marker::PhantomData;

use bytes::{buf::UninitSlice, BufMut, BytesMut};
use deref_derive::{Deref, DerefMut};
use encrypt::{encode_long_first_byte, encode_short_first_byte, encrypt_packet, protect_header};
use enum_dispatch::enum_dispatch;
use header::io::WriteHeader;

use crate::{
    cid::ConnectionId,
    frame::io::{WriteDataFrame, WriteFrame},
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

pub struct PacketWriter<'b, H> {
    buffer: &'b mut [u8],
    hdr_len: usize,
    len_encoding: usize,
    pn: (u64, PacketNumber),
    cursor: usize,
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
    probe_new_path: bool,

    _kind: PhantomData<H>,
}

impl<'b, H> PacketWriter<'b, H> {
    pub fn new(
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

        let cursor = hdr_len + len_encoding + encoded_pn.size();
        Some(Self {
            buffer,
            hdr_len,
            len_encoding,
            pn,
            cursor,
            tag_len,
            ack_eliciting: false,
            in_flight: false,
            probe_new_path: false,
            _kind: PhantomData,
        })
    }

    pub fn pad(&mut self, cnt: usize) {
        self.put_bytes(0, cnt);
    }

    #[inline]
    pub fn is_ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }

    #[inline]
    pub fn is_in_flight(&self) -> bool {
        self.in_flight
    }
}

macro_rules! impl_packet_writer {
    (@long $lh_ty:ty) => {
        impl PacketWriter<'_, $lh_ty> {
            /// Seal the packet and return the remaining length.
            ///
            /// Once the packet is encapsulated, you cannot write any more data to it, you can still encrypt it.
            pub fn seal_packet(&mut self) -> &mut [u8] {
                let buffer = core::mem::take(&mut self.buffer);

                let (packet, remain) = buffer.split_at_mut(self.cursor + self.tag_len);
                self.buffer = packet;

                remain
            }

            /// Extend the packet with the next contiguous buffer.
            ///
            /// This is useful when you regret sealing a packet.
            ///
            /// Panic if the given buffer is not contiguous with the old buffer.
            ///
            /// ``` example, no_run
            /// # use qbase::packet::PacketWriter;
            /// # use qbase::packet::header::InitialHeader;
            /// # let packet_writer: PacketWriter<InitialHeader> = unimplemented!();
            /// let remain = packet_writer.seal_packet();
            /// packet_buffer.extend_packet(remain);
            /// ```
            pub fn extend_packet(&mut self, next: &mut [u8]) {
                if self.buffer.as_ptr().wrapping_add(self.buffer.len()) == next.as_ptr() {
                    let data = self.buffer.as_mut_ptr();
                    let len = self.buffer.len() + next.len();
                    // SAFETY: the new buffer is contiguous with the old buffer, they can be merged.
                    self.buffer = unsafe { core::slice::from_raw_parts_mut(data, len) };
                } else {
                    panic!("extend_packet: the new buffer is not contiguous with the old buffer");
                }
            }

            pub fn encrypt(
                &mut self,
                hpk: &dyn rustls::quic::HeaderProtectionKey,
                pk: &dyn rustls::quic::PacketKey,
            ) -> usize {
                let (actual_pn, encoded_pn) = self.pn;
                encode_long_first_byte(&mut self.buffer[0], encoded_pn.size());

                let pkt_size = self.buffer.len();
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
        }
    };
    (@short $sh_ty:ty) => {
        impl PacketWriter<'_, $sh_ty> {
            pub fn encrypt(
                &mut self,
                key_phase: KeyPhaseBit,
                hpk: &dyn rustls::quic::HeaderProtectionKey,
                pk: &dyn rustls::quic::PacketKey,
            ) -> usize {
                let (actual_pn, encoded_pn) = self.pn;
                encode_short_first_byte(&mut self.buffer[0], encoded_pn.size(), key_phase);

                let pkt_size = self.buffer.len();
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
    };
    (@long $($lh_ty:ty)* $(;$($remain:tt)*)?) => {
        $(impl_packet_writer!(@long $lh_ty);)*
        $(impl_packet_writer!($($remain)*); )?

    };
    (@short $($sh_ty:ty)* $(;$($remain:tt)*)?) => {
        $(impl_packet_writer!(@short $sh_ty);)*
        $(impl_packet_writer!($($remain)*); )?
    };
}

impl_packet_writer! {
    @long InitialHeader HandshakeHeader RetryHeader ZeroRttHeader;
    @short OneRttHeader
}

unsafe impl<H> BufMut for PacketWriter<'_, H> {
    fn remaining_mut(&self) -> usize {
        self.buffer.len() - self.tag_len - self.cursor
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
        let remaining_len = self.remaining_mut();
        UninitSlice::new(&mut self.buffer[self.cursor..][..remaining_len])
    }
}

macro_rules! impl_packet_writer_write_frames {
    // 和FrameType::specs重复了
    (@spec $this:ident NP) => {                                                    $this.probe_new_path = true; };
    (@spec $this:ident NC) => {                                                                                 };
    (@spec $this:ident P ) => { $this.ack_eliciting = true; $this.in_flight = true; $this.probe_new_path = true; };
    (@spec $this:ident N ) => {                             $this.in_flight = true;                              };
    (@spec $this:ident   ) => { $this.ack_eliciting = true; $this.in_flight = true;                              };
    // 实现 WriteFrame
    (@imp_wf  $frame:ident : $hdr:ident $($spec:ident)?) => {
        impl WriteFrame<$crate::frame::$frame> for PacketWriter<'_, $hdr> {
            fn put_frame(&mut self, frame: &$crate::frame::$frame) {
                impl_packet_writer_write_frames!(@spec self $($spec)?);
                // same as BytesMut::chunk_mut
                let body_remaining_len = self.remaining_mut();
                let mut body = &mut self.buffer[self.cursor..][..body_remaining_len];

                body.put_frame(frame);
            }
        }
    };
    // 实现 WriteDataFrame
    (@imp_wdf $frame:ident : $hdr:ident $($spec:ident)?) => {
        impl<D> WriteDataFrame<$crate::frame::$frame, D> for PacketWriter<'_, $hdr>
        where
            D: crate::util::DescribeData,
            for<'a> &'a mut [u8]: WriteDataFrame<$crate::frame::$frame, D>
        {
            fn put_data_frame(&mut self, frame: &$crate::frame::$frame, data: &D) {
                impl_packet_writer_write_frames!(@spec self $($spec)?);
                // same as BytesMut::chunk_mut
                let body_remaining_len = self.remaining_mut();
                let mut body = &mut self.buffer[self.cursor..][..body_remaining_len];

                body.put_data_frame(frame, data);
            }
        }
    };
    // 根据$frame选择需要实现的trait：筛选出DataFrame和非DataFrame
    (@imp  StreamFrame : $hdr:ident $($spec:ident)?) => {
        impl_packet_writer_write_frames!(@imp_wdf StreamFrame  : $hdr $($spec)?);
    };
    (@imp  CryptoFrame : $hdr:ident $($spec:ident)?) => {
        impl_packet_writer_write_frames!(@imp_wdf CryptoFrame  : $hdr $($spec)?);
    };
    (@imp  DatagramFrame : $hdr:ident $($spec:ident)?) => {
        impl_packet_writer_write_frames!(@imp_wdf DatagramFrame: $hdr $($spec)?);
    };
    (@imp  $frame:ident : $hdr:ident $($spec:ident)?) => {
        impl_packet_writer_write_frames!(@imp_wf  $frame       : $hdr $($spec)?);
    };
    // 实现对各种Header的实现
    (@pkts $frame:ident: IH01 $($spec:ident)?) => {
        impl_packet_writer_write_frames!(@imp $frame: InitialHeader   $($spec)?);
        impl_packet_writer_write_frames!(@imp $frame: HandshakeHeader $($spec)?);
        impl_packet_writer_write_frames!(@imp $frame: ZeroRttHeader   $($spec)?);
        impl_packet_writer_write_frames!(@imp $frame: OneRttHeader    $($spec)?);
    };
    (@pkts $frame:ident: IH_1 $($spec:ident)?) => {
        impl_packet_writer_write_frames!(@imp $frame: InitialHeader   $($spec)?);
        impl_packet_writer_write_frames!(@imp $frame: HandshakeHeader $($spec)?);
        impl_packet_writer_write_frames!(@imp $frame: OneRttHeader    $($spec)?);
    };
    (@pkts $frame:ident: __01 $($spec:ident)?) => {
        impl_packet_writer_write_frames!(@imp $frame: HandshakeHeader $($spec)?);
        impl_packet_writer_write_frames!(@imp $frame: OneRttHeader    $($spec)?);
    };
    (@pkts $frame:ident: ___1 $($spec:ident)?) => {
        impl_packet_writer_write_frames!(@imp $frame: OneRttHeader    $($spec)?);
    };
    (@pkts $frame:ident: ih01 $($spec:ident)?) => {
        impl_packet_writer_write_frames!(@imp $frame: InitialHeader   $($spec)?);
        impl_packet_writer_write_frames!(@imp $frame: HandshakeHeader $($spec)?);
        impl_packet_writer_write_frames!(@imp $frame: ZeroRttHeader   $($spec)?);
        impl_packet_writer_write_frames!(@imp $frame: OneRttHeader    $($spec)?);
    };
    ($( $frame:ident: $pkts:ident $($spec:ident)? ;)*) => {
        $(impl_packet_writer_write_frames!(@pkts $frame: $pkts $($spec)?);)*
    }
}

// 与 https://www.rfc-editor.org/rfc/rfc9000.html#frame-types 对应
impl_packet_writer_write_frames! {
//  Frame Type Name           Pkts Spec
    PaddingFrame            : IH01 NP  ;
    PingFrame               : IH01     ;
    AckFrame                : IH01 NC  ;
    ResetStreamFrame        : __01     ;
    StopSendingFrame        : __01     ;
    CryptoFrame             : IH_1     ;
    NewTokenFrame           : ___1 NC  ;
    StreamFrame             : ih01     ;
    MaxDataFrame            : __01     ;
    MaxStreamDataFrame      : __01     ;
    MaxStreamsFrame         : __01     ;
    DataBlockedFrame        : __01     ;
    StreamDataBlockedFrame  : __01     ;
    StreamsBlockedFrame     : __01     ;
    NewConnectionIdFrame    : __01 P   ;
    RetireConnectionIdFrame : __01     ;
    PathChallengeFrame      : __01 P   ;
    PathResponseFrame       : __01 P   ;
    ConnectionCloseFrame    : ih01 N   ;
    HandshakeDoneFrame      : ___1     ;
    // rfc9221
    DatagramFrame           : __01 N   ;
}
