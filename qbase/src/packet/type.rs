use super::{KeyPhaseBit, PacketNumber};
use crate::error::Error;
use deref_derive::Deref;

pub mod long;
pub mod short;

/// header form bit
const HEADER_FORM_MASK: u8 = 0x80;
/// The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotiation packet.
const FIXED_BIT: u8 = 0x40;

/// After removing the packet header protection, the clear first byte part,
/// 'R' represents the reserved bits. The long packet header is 0x0C, and
/// the short packet header is 0x18.
#[derive(Debug, Clone, Copy, Deref)]
pub(super) struct ClearBits<const R: u8>(#[deref] pub(super) u8);

pub(super) type ShortClearBits = ClearBits<0x18>;
pub(super) type LongClearBits = ClearBits<0xC>;

impl<const R: u8> ClearBits<R> {
    pub fn by(pn: &PacketNumber) -> Self {
        Self(R | (pn.size() as u8 - 1))
    }
}

impl ShortClearBits {
    pub(super) fn set_key_phase_bit(&mut self, key_phase_bit: KeyPhaseBit) {
        match key_phase_bit {
            KeyPhaseBit::On => self.0 |= key_phase_bit.value(),
            KeyPhaseBit::Off => self.0 &= key_phase_bit.value(),
        }
    }

    pub(super) fn key_phase_bit(&self) -> KeyPhaseBit {
        KeyPhaseBit::from(self.0)
    }
}

impl<const R: u8> From<u8> for ClearBits<R> {
    fn from(byte: u8) -> Self {
        Self(byte)
    }
}

pub trait GetPacketNumberLength {
    /// The least significant two bits (those with a mask of 0x03)
    /// of byte 0 contain the length of the Packet Number field
    const PN_LEN_MASK: u8 = 0x03;

    /// The value included prior to protection MUST be set to 0.
    /// An endpoint MUST treat receipt of a packet that has a non-zero value for these bits
    /// after removing both packet and header protection as a connection error of type
    /// PROTOCOL_VIOLATION. Discarding such a packet after only removing header protection
    /// can expose the endpoint to attacks.
    ///
    /// see [Section 17.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.2) and
    /// [Section 17.3.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1-4.8) of QUIC.
    fn pn_len(&self) -> Result<u8, Error>;
}

impl<const R: u8> GetPacketNumberLength for ClearBits<R> {
    fn pn_len(&self) -> Result<u8, Error> {
        let reserved_bit = self.0 & R;
        if reserved_bit == 0 {
            Ok((self.0 & Self::PN_LEN_MASK) + 1)
        } else {
            Err(Error::new_with_default_fty(
                crate::error::ErrorKind::ProtocolViolation,
                format!("invalid reserved bits {reserved_bit}"),
            ))
        }
    }
}

/// The Type is only extracted from the first 3 or 4 bits of the first byte, these contents
/// are not protected, there is no distinction between ciphertext and plaintext.
/// For simplicity and future-oriented considerations, the Version of the long packet header
/// is also considered part of the Type, such as the Initial packet of V1 version,
/// That is, the Initial packet only makes sense under the V1 version, and it is uncertain
/// whether future versions of QUIC will still have Initial packets.
/// The SpinBit of the short packet header is part of the short packet header Type, but for
/// simplicity, the SpinBit is also part of the 1RTT header.
#[derive(Debug, Clone, Copy)]
pub enum Type {
    Long(long::Type),
    Short(short::OneRtt),
}

impl Type {
    #[inline]
    pub fn encoding_size(&self) -> usize {
        match self {
            Type::Short(_) => 1,
            Type::Long(_) => 5,
        }
    }
}

pub mod ext {
    use super::{long::ext::WriteLongType, short::WriteShortType, *};
    use bytes::BufMut;

    pub fn be_packet_type(input: &[u8]) -> nom::IResult<&[u8], Type> {
        let (remain, ty) = nom::number::streaming::be_u8(input)?;
        if ty & HEADER_FORM_MASK == 0 {
            Ok((remain, Type::Short(short::OneRtt::from(ty))))
        } else {
            let (remain, ty) = long::ext::parse_long_type(ty)(remain)?;
            Ok((remain, Type::Long(ty)))
        }
    }

    pub trait WritePacketType {
        fn put_packet_type(&mut self, ty: &Type);
    }

    impl<B: BufMut> WritePacketType for B {
        fn put_packet_type(&mut self, ty: &Type) {
            match ty {
                Type::Short(one_rtt) => self.put_short_type(one_rtt),
                Type::Long(long_type) => self.put_long_type(long_type),
            }
        }
    }
}
