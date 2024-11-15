use std::marker::PhantomData;

use bytes::{buf::UninitSlice, BufMut};

use super::{
    encrypt::{encode_long_first_byte, encode_short_first_byte, encrypt_packet, protect_header},
    header::{io::WriteHeader, HandshakeHeader, InitialHeader, OneRttHeader, ZeroRttHeader},
    EncodeHeader, KeyPhaseBit, PacketNumber, WritePacketNumber,
};
use crate::{
    frame::io::{WriteDataFrame, WriteFrame},
    varint::{EncodeBytes, VarInt, WriteVarInt},
};

pub struct PacketWriter<'b, H> {
    buffer: &'b mut [u8],
    hdr_size: usize,
    len_size: usize,
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

    _header: PhantomData<H>,
}

#[derive(Debug)]
pub struct CompletePacket {
    pn: u64,
    size: usize,
    ack_eliciting: bool,
    in_flight: bool,
    probe_new_path: bool,
}

// 不可篡改
impl CompletePacket {
    #[inline]
    pub fn packet_number(&self) -> u64 {
        self.pn
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    #[inline]
    pub fn is_ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }

    #[inline]
    pub fn is_in_flight(&self) -> bool {
        self.in_flight
    }

    #[inline]
    pub fn probe_new_path(&self) -> bool {
        self.probe_new_path
    }
}

pub type InitialPacketWriter<'b> = PacketWriter<'b, InitialHeader>;
pub type HandshakePacketWriter<'b> = PacketWriter<'b, HandshakeHeader>;
// pub type RetryPacketWriter<'b> = PacketWriter<'b, RetryHeader>;
pub type ZeroRttPacketWriter<'b> = PacketWriter<'b, ZeroRttHeader>;
pub type OneRttPacketWriter<'b> = PacketWriter<'b, OneRttHeader>;

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
        let hdr_size = header.size();
        let len_size = header.length_encoding();
        if buffer.len() < hdr_size + len_size + 20 {
            return None;
        }

        let (mut hdr_buf, mut payload_buf) = buffer.split_at_mut(hdr_size + len_size);
        // hdr_buf: header + len
        hdr_buf.put_header(header);
        // payload_buf: pn + payload + tag
        let encoded_pn = pn.1;
        payload_buf.put_packet_number(encoded_pn);

        let cursor = hdr_size + len_size + encoded_pn.size();
        Some(Self {
            buffer,
            hdr_size,
            len_size,
            pn,
            cursor,
            tag_len,
            ack_eliciting: false,
            in_flight: false,
            probe_new_path: false,
            _header: PhantomData,
        })
    }

    pub fn is_empty(&self) -> bool {
        let payload_start = self.hdr_size + self.len_size + self.pn.1.size();
        payload_start == self.cursor
    }

    pub fn pad(&mut self, cnt: usize) {
        self.put_bytes(0, cnt);
    }
}

macro_rules! impl_packet_writer {
    (@long $lh_ty:ty) => {
        impl<'b> PacketWriter<'b, $lh_ty> {
            /// Seal the packet and return the remaining length.
            ///
            /// Once the packet is encapsulated, you cannot write any more data to it, you can still encrypt it.
            pub fn seal_packet(&mut self) -> &'b mut [u8] {

                let buffer = core::mem::take(&mut self.buffer);
                // hdr_size + len_size + 20 为最小包大小
                let end = (self.hdr_size + self.len_size + 20).max(self.cursor + self.tag_len);

                let (packet, remain) = buffer.split_at_mut(end);
                self.buffer = packet;

                remain
            }

            /// Extend the packet with the next contiguous buffer.
            ///
            /// This is useful when you regret sealing a packet.
            ///
            /// Panic if the given buffer is not contiguous with the old buffer.
            ///
            /// ``` no_run
            /// # use qbase::packet::PacketWriter;
            /// # use qbase::packet::header::InitialHeader;
            /// # let packet_writer: PacketWriter<InitialHeader> = unimplemented!();
            /// let remain = packet_writer.seal_packet();
            /// packet_buffer.extend_packet(remain);
            /// ```
            pub fn extend_packet(&mut self, next: &'b mut [u8]) {
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
                self,
                hpk: &dyn rustls::quic::HeaderProtectionKey,
                pk: &dyn rustls::quic::PacketKey,
            ) -> CompletePacket {
                let (actual_pn, encoded_pn) = self.pn;
                encode_long_first_byte(&mut self.buffer[0], encoded_pn.size());

                let pkt_size = self.buffer.len();
                // 剩下的缓冲区完全可以认为是“未初始化的”，填充0
                self.buffer[self.cursor..pkt_size - self.tag_len].fill(0);

                let payload_len = pkt_size - self.hdr_size - self.len_size;
                let mut length_buf = &mut self.buffer[self.hdr_size..][..self.len_size];
                length_buf.encode_varint(&VarInt::try_from(payload_len).unwrap(), EncodeBytes::Two);

                encrypt_packet(
                    pk,
                    actual_pn,
                    &mut self.buffer[..pkt_size],
                    self.hdr_size + self.len_size + encoded_pn.size(),
                );
                protect_header(
                    hpk,
                    &mut self.buffer[..pkt_size],
                    self.hdr_size,
                    encoded_pn.size(),
                );
                CompletePacket {
                    pn: actual_pn,
                    size: pkt_size,
                    ack_eliciting: self.ack_eliciting,
                    in_flight: self.in_flight,
                    probe_new_path: self.probe_new_path,
                }
            }
        }
    };
    (@short $sh_ty:ty) => {
        impl PacketWriter<'_, $sh_ty> {
            pub fn encrypt(
                self,
                key_phase: KeyPhaseBit,
                hpk: &dyn rustls::quic::HeaderProtectionKey,
                pk: &dyn rustls::quic::PacketKey,
            ) -> CompletePacket {
                let (actual_pn, encoded_pn) = self.pn;
                encode_short_first_byte(&mut self.buffer[0], encoded_pn.size(), key_phase);

                let pkt_size = self.buffer.len();
                // 剩下的缓冲区完全可以认为是“未初始化的”，填充0
                self.buffer[self.cursor..pkt_size - self.tag_len].fill(0);

                encrypt_packet(
                    pk,
                    actual_pn,
                    &mut self.buffer[..pkt_size],
                    self.hdr_size + self.len_size + encoded_pn.size(),
                );
                protect_header(
                    hpk,
                    &mut self.buffer[..pkt_size],
                    self.hdr_size,
                    encoded_pn.size(),
                );
                CompletePacket {
                    pn: actual_pn,
                    size: pkt_size,
                    ack_eliciting: self.ack_eliciting,
                    in_flight: self.in_flight,
                    probe_new_path: self.probe_new_path,
                }
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
    @long InitialHeader HandshakeHeader ZeroRttHeader;
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
        let pkt_size = self.buffer.len();
        UninitSlice::new(&mut self.buffer[self.cursor..pkt_size - self.tag_len])
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
                println!("put frame: {}", core::any::type_name::<$crate::frame::$frame>());
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
                println!("put frame: {}", core::any::type_name::<$crate::frame::$frame>());
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
    // 对各种包的实现
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
        impl_packet_writer_write_frames!(@imp $frame: ZeroRttHeader   $($spec)?);
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
    PathResponseFrame       : ___1 P   ;
    ConnectionCloseFrame    : ih01 N   ;
    HandshakeDoneFrame      : ___1     ;
    // rfc9221
    DatagramFrame           : __01 N   ;
}
