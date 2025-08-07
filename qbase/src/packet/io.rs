use std::{marker::PhantomData, mem};

use bytes::BytesMut;
use nom::{Parser, multi::length_data};

use super::{
    error::Error,
    header::io::be_header,
    r#type::{Type, io::be_packet_type},
    *,
};
use crate::{
    frame::{
        EncodeSize,
        io::{WriteDataFrame, WriteFrame},
    },
    net::tx::Signals,
    util::ContinuousData,
    varint::be_varint,
};

/// Parse the payload of a packet.
///
/// - For long packets, the payload is a [`nom::multi::length_data`].
/// - For 1-RTT packet, the payload is the remaining content of the datagram.
fn be_payload(
    pkty: Type,
    datagram: &mut BytesMut,
    remain_len: usize,
) -> Result<(BytesMut, usize), Error> {
    let offset = datagram.len() - remain_len;
    let input = &datagram[offset..];
    let (remain, payload) = length_data(be_varint).parse(input).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => Error::IncompleteHeader(pkty, ne.to_string()),
        _ => unreachable!("parsing packet header never generates error or failure"),
    })?;
    let payload_len = payload.len();
    if payload_len < 20 {
        // The payload needs at least 20 bytes to have enough samples to remove the packet header protection.
        tracing::error!("   Cause by: parsing {:?} packet", pkty);
        return Err(Error::UnderSampling(payload.len()));
    }
    let packet_length = datagram.len() - remain.len();
    let bytes = datagram.split_to(packet_length);
    Ok((bytes, packet_length - payload_len))
}

/// Parse the QUIC packet from the datagram, given the length of the DCID.
/// Returns the parsed packet or an error, and the datagram removed the packet's content.
pub fn be_packet(datagram: &mut BytesMut, dcid_len: usize) -> Result<Packet, Error> {
    let input = datagram.as_ref();
    let (remain, pkty) = be_packet_type(input).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => Error::IncompleteType(ne.to_string()),
        nom::Err::Error(e) => e,
        _ => unreachable!("parsing packet type never generates failure"),
    })?;
    let (remain, header) = be_header(pkty, dcid_len, remain).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => Error::IncompleteHeader(pkty, ne.to_string()),
        _ => unreachable!("parsing packet header never generates error or failure"),
    })?;
    match header {
        Header::VN(header) => {
            datagram.clear();
            Ok(Packet::VN(header))
        }
        Header::Retry(header) => {
            datagram.clear();
            Ok(Packet::Retry(header))
        }
        Header::Initial(header) => {
            let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Long(long::DataHeader::Initial(header)),
                bytes,
                offset,
            }))
        }
        Header::ZeroRtt(header) => {
            let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Long(long::DataHeader::ZeroRtt(header)),
                bytes,
                offset,
            }))
        }
        Header::Handshake(header) => {
            let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Long(long::DataHeader::Handshake(header)),
                bytes,
                offset,
            }))
        }
        Header::OneRtt(header) => {
            if remain.len() < 20 {
                // The payload needs at least 20 bytes to have enough samples to remove the packet header protection.
                tracing::error!("   Cause by: parsing 1-RTT packet");
                return Err(Error::UnderSampling(remain.len()));
            }
            let remain_len = remain.len();
            let bytes = mem::replace(datagram, BytesMut::new());
            let offset = bytes.len() - remain_len;
            datagram.clear();
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Short(header),
                bytes,
                offset,
            }))
        }
    }
}

pub trait ProductHeader<H> {
    fn new_header(&self) -> Result<H, Signals>;
}

pub trait PacketSpace<H> {
    type PacketAssembler<'b>: AssemblePacket
    where
        Self: 'b;

    fn new_packet<'b>(
        &'b self,
        header: H,
        buffer: &'b mut [u8],
    ) -> Result<Self::PacketAssembler<'b>, Signals>;
}

pub trait Package<Into: ?Sized> {
    type Output;

    fn dump(&mut self, into: &mut Into) -> Result<Self::Output, Signals>;
}

impl<Into: BufMut + ?Sized, P: Package<Into> + ?Sized> Package<Into> for &mut P {
    type Output = P::Output;

    #[inline]
    fn dump(&mut self, into: &mut Into) -> Result<Self::Output, Signals> {
        P::dump(self, into)
    }
}

impl<Into: BufMut + ?Sized, P: Package<Into> + ?Sized> Package<Into> for Box<P> {
    type Output = P::Output;

    #[inline]
    fn dump(&mut self, into: &mut Into) -> Result<Self::Output, Signals> {
        P::dump(self, into)
    }
}

impl<Into: BufMut + ?Sized, P: Package<Into>> Package<Into> for Option<P> {
    type Output = P::Output;

    #[inline]
    fn dump(&mut self, into: &mut Into) -> Result<Self::Output, Signals> {
        self.take()
            .map_or_else(|| Err(Signals::empty()), |mut package| package.dump(into))
    }
}

impl<Into: BufMut + ?Sized, P: Package<Into>> Package<Into> for [P] {
    type Output = Vec<P::Output>;

    #[inline]
    fn dump(&mut self, into: &mut Into) -> Result<Self::Output, Signals> {
        let origin = into.remaining_mut();
        let mut outputs = Vec::with_capacity(self.len());
        let mut signals = Signals::empty();
        for package in self {
            match package.dump(into) {
                Err(s) => signals |= s,
                Ok(output) => outputs.push(output),
            }
        }

        (origin != into.remaining_mut())
            .then_some(outputs)
            .ok_or(signals)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Frame<F>(F);

impl<Into, F> Package<Into> for Frame<F>
where
    F: EncodeSize + Clone,
    Into: BufMut + MarshalFrame<F> + ?Sized,
{
    type Output = ();

    #[inline]
    fn dump(&mut self, into: &mut Into) -> Result<(), Signals> {
        if self.0.encoding_size() > into.remaining_mut() {
            return Err(Signals::CONGESTION);
        }
        into.dump_frame(self.0.clone());
        Ok(())
    }
}

pub fn frame<F>(frame: F) -> Frame<F>
where
    F: EncodeSize + Clone,
{
    Frame(frame)
}

#[derive(Debug, Clone, Copy)]
pub struct PathFrame<F>(F);

impl<Into, F> Package<Into> for PathFrame<F>
where
    F: EncodeSize + Clone,
    Into: BufMut + MarshalPathFrame<F> + ?Sized,
{
    type Output = ();

    #[inline]
    fn dump(&mut self, into: &mut Into) -> Result<(), Signals> {
        if self.0.encoding_size() > into.remaining_mut() {
            return Err(Signals::CONGESTION);
        }
        into.dump_path_frame(self.0.clone());
        Ok(())
    }
}

pub fn path_frame<F>(frame: F) -> PathFrame<F>
where
    F: EncodeSize + Clone,
{
    PathFrame(frame)
}

pub struct DataFrame<F, D>(F, D);

impl<Into, F, D> Package<Into> for DataFrame<F, D>
where
    F: EncodeSize + Clone,
    D: Clone,
    Into: BufMut + MarshalDataFrame<F, D> + ?Sized,
{
    type Output = ();

    #[inline]
    fn dump(&mut self, into: &mut Into) -> Result<(), Signals> {
        if self.0.encoding_size() > into.remaining_mut() {
            return Err(Signals::CONGESTION);
        }
        into.dump_frame_with_data(self.0.clone(), self.1.clone());
        Ok(())
    }
}

pub fn data_frame<F, D>(frame: F, data: D) -> DataFrame<F, D>
where
    F: EncodeSize + Clone,
    D: Clone,
{
    DataFrame(frame, data)
}

#[derive(Debug, Clone, Copy)]
pub struct FnPackage<F>(F);

impl<Into, F, Output> Package<Into> for FnPackage<F>
where
    Into: ?Sized,
    F: for<'a> FnMut(&'a mut Into) -> Result<Output, Signals>,
{
    type Output = Output;

    #[inline]
    fn dump(&mut self, into: &mut Into) -> Result<Output, Signals> {
        (self.0)(into)
    }
}

pub struct Empty<O>(PhantomData<O>);

impl<Into: ?Sized, O> Package<Into> for Empty<O> {
    type Output = O;

    #[inline]
    fn dump(&mut self, _into: &mut Into) -> Result<O, Signals> {
        Err(Signals::empty())
    }
}

#[inline]
pub fn empty<O>() -> Empty<O> {
    Empty(PhantomData)
}

#[inline]
pub fn fn_package<Into, F, Output>(f: F) -> FnPackage<F>
where
    Into: ?Sized,
    F: for<'a> FnMut(&'a mut Into) -> Result<Output, Signals>,
{
    FnPackage(f)
}

pub struct PadTo20;

impl<'b, P> Package<P> for PadTo20
where
    P: AsRef<PacketWriter<'b>> + BufMut + ?Sized,
{
    type Output = ();

    #[inline]
    fn dump(&mut self, into: &mut P) -> Result<(), Signals> {
        let packet = into.as_ref();
        match packet.payload_len() + packet.tag_len() {
            _ if packet.is_empty() => Err(Signals::empty()),
            len if len < 20 => {
                into.put_bytes(0, 20 - len);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[inline]
pub fn pad_to_20() -> PadTo20 {
    PadTo20
}

pub struct PadToFull;

impl<'b, P> Package<P> for PadToFull
where
    P: AsRef<PacketWriter<'b>> + BufMut + ?Sized,
{
    type Output = ();

    #[inline]
    fn dump(&mut self, into: &mut P) -> Result<(), Signals> {
        let packet = into.as_ref();
        match packet.payload_len() + packet.tag_len() {
            _ if packet.is_empty() => Err(Signals::empty()),
            len if len < packet.buffer().len() => {
                into.put_bytes(0, packet.remaining_mut());
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[inline]
pub fn pad_to_full() -> PadToFull {
    PadToFull
}

pub struct PadProbe;

impl<'b, P> Package<P> for PadProbe
where
    P: AsRef<PacketWriter<'b>> + BufMut + ?Sized,
{
    type Output = ();

    #[inline]
    fn dump(&mut self, into: &mut P) -> Result<(), Signals> {
        if into.as_ref().is_probe_new_path() {
            return pad_to_full().dump(into);
        }
        Err(Signals::empty())
    }
}

#[inline]
pub fn pad_probe() -> PadProbe {
    PadProbe
}

#[derive(Debug, Clone, Copy)]
pub struct Repeat<P>(P);

impl<Into: ?Sized + BufMut, P: Package<Into>> Package<Into> for Repeat<P> {
    type Output = Vec<P::Output>;

    #[inline]
    fn dump(&mut self, into: &mut Into) -> Result<Vec<P::Output>, Signals> {
        let origin = into.remaining_mut();
        let mut outputs = Vec::new();
        let signals = loop {
            match self.0.dump(into) {
                Err(s) => break s,
                Ok(output) => outputs.push(output),
            }
        };

        (origin != into.remaining_mut())
            .then_some(outputs)
            .ok_or(signals)
    }
}

pub fn repeat<P>(package: P) -> Repeat<P> {
    Repeat(package)
}

macro_rules! impl_package_for_tuple {
    () => {};
    ($head:ident $($tail:ident)*) => {
        impl_package_for_tuple!(@imp $head $($tail)*);
        impl_package_for_tuple!(           $($tail)*);

    };
    (@imp $($t:ident)*) => {
        impl<Into: BufMut + ?Sized, $($t: Package<Into>),*> Package<Into> for ($($t,)*) {
            type Output = ($(Option<$t::Output>,)*);

            #[inline]
            fn dump(&mut self, into: &mut Into) -> Result<Self::Output, Signals> {
                let origin = into.remaining_mut();
                let mut signals = Signals::empty();

                #[allow(non_snake_case)]
                let ($($t,)*) = self;

                $(
                #[allow(non_snake_case)]
                let $t = match $t.dump(into) {
                    Ok(output) => Some(output),
                    Err(s) => {
                        signals |= s;
                        None
                    }
                };
                )*


                (origin != into.remaining_mut())
                    .then_some(($($t,)*))
                    .ok_or(signals)
            }
        }
    }
}

impl_package_for_tuple! {
    Z Y X W V U T S R Q P O N M L K J I H G F E D C B A
}

pub enum Keys {
    LongHeaderPacket {
        keys: DirectionalKeys,
    },
    ShortHeaderPacket {
        keys: DirectionalKeys,
        key_phase: KeyPhaseBit,
    },
}

impl Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LongHeaderPacket { .. } => f
                .debug_struct("LongHeaderPacket")
                .field("keys", &"...")
                .finish(),
            Self::ShortHeaderPacket { key_phase, .. } => f
                .debug_struct("ShortHeaderPacket")
                .field("keys", &"...")
                .field("key_phase", key_phase)
                .finish(),
        }
    }
}

impl Keys {
    fn hpk(&self) -> &dyn rustls::quic::HeaderProtectionKey {
        match self {
            Self::LongHeaderPacket { keys } | Self::ShortHeaderPacket { keys, .. } => {
                keys.header.as_ref()
            }
        }
    }

    fn pk(&self) -> &dyn rustls::quic::PacketKey {
        match self {
            Self::LongHeaderPacket { keys } | Self::ShortHeaderPacket { keys, .. } => {
                keys.packet.as_ref()
            }
        }
    }

    fn key_phase(&self) -> Option<KeyPhaseBit> {
        match self {
            Self::LongHeaderPacket { .. } => None,
            Self::ShortHeaderPacket { key_phase, .. } => Some(*key_phase),
        }
    }
}

#[derive(Debug, CopyGetters)]
pub struct PacketLayout {
    hdr_len: usize,
    len_encoding: usize,

    cursor: usize,
    end: usize,

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
    #[getset(get_copy = "pub")]
    probe_new_path: bool,
}

impl PacketLayout {
    pub fn payload_len(&self) -> usize {
        self.cursor - self.hdr_len - self.len_encoding
    }

    pub fn add_frame(&mut self, frame: &impl FrameFeture) {
        self.ack_eliciting |= !frame.specs().contain(Spec::NonAckEliciting);
        self.in_flight |= !frame.specs().contain(Spec::CongestionControlFree);
        self.probe_new_path |= frame.specs().contain(Spec::ProbeNewPath);
    }
}

pub struct PacketWriter<'b> {
    keys: Keys,
    pn: (u64, PacketNumber),
    layout: PacketLayout,
    buffer: &'b mut [u8],
}

impl<'b> PacketWriter<'b> {
    pub fn new_long<S>(
        header: &LongHeader<S>,
        buffer: &'b mut [u8],
        pn: (u64, PacketNumber),
        keys: DirectionalKeys,
    ) -> Result<Self, Signals>
    where
        S: EncodeHeader,
        for<'a> &'a mut [u8]: WriteHeader<LongHeader<S>>,
    {
        let hdr_len = header.size();
        let len_encoding = header.length_encoding();
        if buffer.len() < hdr_len + len_encoding + 20 {
            return Err(Signals::CONGESTION);
        }

        let (mut hdr_buf, mut payload_buf) = buffer.split_at_mut(hdr_len + len_encoding);
        let encoded_pn = pn.1;
        hdr_buf.put_header(header);
        payload_buf.put_packet_number(encoded_pn);

        let cursor = hdr_len + len_encoding + encoded_pn.size();
        Ok(Self {
            pn,
            layout: PacketLayout {
                hdr_len,
                len_encoding,
                cursor,
                end: buffer.len() - keys.packet.tag_len(),
                ack_eliciting: false,
                in_flight: false,
                probe_new_path: false,
            },
            keys: Keys::LongHeaderPacket { keys },
            buffer,
        })
    }

    pub fn new_short(
        header: &OneRttHeader,
        buffer: &'b mut [u8],
        pn: (u64, PacketNumber),
        keys: DirectionalKeys,
        key_phase: KeyPhaseBit,
    ) -> Result<Self, Signals> {
        let hdr_len = header.size();
        if buffer.len() < hdr_len + 20 {
            return Err(Signals::CONGESTION);
        }

        let (mut hdr_buf, mut payload_buf) = buffer.split_at_mut(hdr_len);
        let encoded_pn = pn.1;
        hdr_buf.put_header(header);
        payload_buf.put_packet_number(encoded_pn);
        Ok(Self {
            pn,
            layout: PacketLayout {
                hdr_len,
                len_encoding: 0,
                cursor: hdr_len + encoded_pn.size(),
                end: buffer.len() - keys.packet.tag_len(),
                ack_eliciting: false,
                in_flight: false,
                probe_new_path: false,
            },
            keys: Keys::ShortHeaderPacket { keys, key_phase },
            buffer,
        })
    }

    #[inline]
    pub fn pn(&self) -> u64 {
        self.pn.0
    }

    #[inline]
    pub fn buffer(&self) -> &[u8] {
        self.buffer
    }

    #[inline]
    pub fn is_short_header(&self) -> bool {
        self.keys.key_phase().is_some()
    }

    #[inline]
    pub fn is_ack_eliciting(&self) -> bool {
        self.layout.ack_eliciting
    }

    #[inline]
    pub fn in_flight(&self) -> bool {
        self.layout.in_flight
    }

    #[inline]
    pub fn is_probe_new_path(&self) -> bool {
        self.layout.probe_new_path
    }

    #[inline]
    pub fn payload_len(&self) -> usize {
        self.layout.payload_len()
    }

    #[inline]
    pub fn tag_len(&self) -> usize {
        self.keys.pk().tag_len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.payload_len() == self.pn.1.size()
    }

    #[inline]
    pub fn packet_len(&self) -> usize {
        self.layout.cursor + self.keys.pk().tag_len()
    }
}

unsafe impl BufMut for PacketWriter<'_> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.layout.end - self.layout.cursor
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        if self.remaining_mut() < cnt {
            panic!(
                "advance out of bounds: the len is {} but advancing by {}",
                cnt,
                self.remaining_mut()
            );
        }

        self.layout.cursor += cnt;
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let range = self.layout.cursor..self.layout.end;
        UninitSlice::new(&mut self.buffer[range])
    }
}

impl<F> MarshalFrame<F> for PacketWriter<'_>
where
    F: FrameFeture,
    Self: WriteFrame<F>,
{
    #[inline]
    fn dump_frame(&mut self, frame: F) -> Option<F> {
        self.layout.add_frame(&frame);
        self.put_frame(&frame);
        Some(frame)
    }
}

impl<F> MarshalPathFrame<F> for PacketWriter<'_>
where
    F: FrameFeture,
    Self: WriteFrame<F>,
{
    #[inline]
    fn dump_path_frame(&mut self, frame: F) -> Option<F> {
        self.layout.add_frame(&frame);
        self.put_frame(&frame);
        Some(frame)
    }
}

impl<F, D> MarshalDataFrame<F, D> for PacketWriter<'_>
where
    D: ContinuousData,
    F: FrameFeture,
    Self: WriteDataFrame<F, D>,
{
    #[inline]
    fn dump_frame_with_data(&mut self, frame: F, data: D) -> Option<F> {
        self.layout.add_frame(&frame);
        self.put_data_frame(&frame, &data);
        Some(frame)
    }
}

#[derive(Debug, CopyGetters, Clone, Copy)]
pub struct FinalPacketLayout {
    #[getset(get_copy = "pub")]
    pn: u64,
    #[getset(get_copy = "pub")]
    sent_bytes: usize,
    #[getset(get_copy = "pub")]
    is_ack_eliciting: bool,
    #[getset(get_copy = "pub")]
    in_flight: bool,
}

pub trait AssemblePacket: BufMut {
    #[inline]
    fn assemble_packet<O>(
        &mut self,
        package: &mut dyn Package<Self, Output = O>,
    ) -> Result<O, Signals> {
        package.dump(self)
    }

    fn encrypt_and_protect_packet(self) -> FinalPacketLayout;
}

impl AssemblePacket for PacketWriter<'_> {
    fn encrypt_and_protect_packet(self) -> FinalPacketLayout {
        use crate::{
            packet::encrypt::*,
            varint::{EncodeBytes, VarInt, WriteVarInt},
        };

        let Self {
            keys,
            pn: (actual_pn, encoded_pn),
            layout,
            buffer,
        } = self;

        let payload_len = layout.payload_len();
        let tag_len = keys.pk().tag_len();

        let pn_len = encoded_pn.size();
        let pkt_size = layout.cursor + tag_len;

        assert!(
            payload_len + tag_len >= 20,
            "The payload and tag needs at least 20 bytes to have enough samples for the packet header protection."
        );

        if let Some(key_phase) = keys.key_phase() {
            encode_short_first_byte(&mut buffer[0], pn_len, key_phase);

            let pk = keys.pk();
            let payload_offset = layout.hdr_len;
            let body_offset = payload_offset + pn_len;
            encrypt_packet(pk, actual_pn, &mut buffer[..pkt_size], body_offset);

            let hpk = keys.hpk();
            protect_header(hpk, &mut buffer[..pkt_size], payload_offset, pn_len);
        } else {
            let packet_len = payload_len + tag_len;
            let len_buffer_range = layout.hdr_len..layout.hdr_len + layout.len_encoding;
            let mut len_buf = &mut buffer[len_buffer_range];
            len_buf.encode_varint(&VarInt::try_from(packet_len).unwrap(), EncodeBytes::Two);

            encode_long_first_byte(&mut buffer[0], pn_len);

            let pk = keys.pk();
            let payload_offset = layout.hdr_len + layout.len_encoding;
            let body_offset = payload_offset + pn_len;
            encrypt_packet(pk, actual_pn, &mut buffer[..pkt_size], body_offset);

            let hpk = keys.hpk();
            protect_header(hpk, &mut buffer[..pkt_size], payload_offset, pn_len);
        }
        FinalPacketLayout {
            pn: actual_pn,
            sent_bytes: pkt_size,
            is_ack_eliciting: layout.ack_eliciting,
            in_flight: layout.in_flight,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{frame::CryptoFrame, varint::VarInt};

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

        let keys = DirectionalKeys {
            packet: Arc::new(TransparentKeys),
            header: Arc::new(TransparentKeys),
        };

        let mut writer = PacketWriter::new_long(&header, &mut buffer, pn, keys).unwrap();
        let frame = CryptoFrame::new(VarInt::from_u32(0), VarInt::from_u32(12));
        writer.dump_frame_with_data(frame, "client_hello".as_bytes());
        assert!(writer.is_ack_eliciting());
        assert!(writer.in_flight());

        let final_packet_layout = writer.encrypt_and_protect_packet();
        assert!(final_packet_layout.is_ack_eliciting());
        assert!(final_packet_layout.in_flight());
        assert_eq!(final_packet_layout.sent_bytes(), 69);
        assert_eq!(
            &buffer[..final_packet_layout.sent_bytes()],
            [
                // initial packet:
                // header form (1) = 1,, long header
                // fixed bit (1) = 1,
                // long packet type (2) = 0, initial packet
                // reserved bits (2) = 0,
                // packet number length (2) = 0, 1 byte
                193, // first byte
                0, 0, 0, 1, // quic version
                // destination connection id, "testdcid"
                8, // dcid length
                b't', b'e', b's', b't', b'd', b'c', b'i', b'd', // dcid bytes
                // source connection id, "testscid"
                8, // scid length
                b't', b'e', b's', b't', b's', b'c', b'i', b'd', // scid bytes
                10,   // token length, no token
                b't', b'e', b's', b't', b'_', b't', b'o', b'k', b'e', b'n', // token bytes
                64, 33, // payload length, 2 bytes encoded varint
                0, 0, // encoded packet number
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
