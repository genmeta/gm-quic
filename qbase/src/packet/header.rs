use crate::error::Error as QuicError;
use deref_derive::{Deref, DerefMut};
use enum_dispatch::enum_dispatch;

pub mod long;
pub mod short;

pub use long::{
    ext::LongHeaderBuilder, PlainHandshakeHeader, PlainInitialHeader, PlainZeroRTTHeader,
    ProtectedHandshakeHeader, ProtectedInitialHeader, ProtectedZeroRTTHeader, RetryHeader,
    VersionNegotiationHeader,
};
pub use short::{PlainOneRttHeader, ProtectedOneRttHeader};

/// header form bit
pub const HEADER_FORM_MASK: u8 = 0x80;
pub const LONG_HEADER_BIT: u8 = 0x80;
const SHORT_HEADER_BIT: u8 = 0x00;
/// The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotiation packet.
const FIXED_BIT: u8 = 0x40;
/// The next two bits (those with a mask of 0x30) of byte 0 contain a packet type.
const LONG_PACKET_TYPE_MASK: u8 = 0x30;
const INITIAL_PACKET_TYPE: u8 = 0x00;
const ZERO_RTT_PACKET_TYPE: u8 = 0x10;
const HANDSHAKE_PACKET_TYPE: u8 = 0x20;
const RETRY_PACKET_TYPE: u8 = 0x30;
/// The least significant two bits (those with a mask of 0x03)
/// of byte 0 contain the length of the Packet Number field
const PN_LEN_MASK: u8 = 0x03;

pub trait Protect {}

pub trait GetLength {
    fn get_length(&self) -> usize;
}

pub trait GetVersion {
    fn get_version(&self) -> u32;
}

use super::GetDcid;

#[enum_dispatch]
pub trait BeProtected {
    fn cipher_packet_type(&self) -> u8;
}

#[enum_dispatch]
pub trait RemoveProtection {
    fn remove_protection(self, plain_packet_type: u8) -> Result<u8, QuicError>;
}

pub trait BePlain {
    /// The value included prior to protection MUST be set to 0.
    /// An endpoint MUST treat receipt of a packet that has a non-zero value for these bits
    /// after removing both packet and header protection as a connection error of type
    /// PROTOCOL_VIOLATION. Discarding such a packet after only removing header protection
    /// can expose the endpoint to attacks.
    ///
    /// see [Section 17.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.2) and
    /// [Section 17.3.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1-4.8) of QUIC.
    fn pn_len(&self) -> Result<u8, QuicError>;
}

#[derive(Debug, Clone, Deref, DerefMut)]
pub struct PlainHeaderWrapper<H: BeProtected>(#[deref] H);

#[derive(Debug, Clone)]
#[enum_dispatch(BeProtected, GetDcid, RemoveProtection)]
pub enum ProtectedHeader {
    Initial(ProtectedInitialHeader),
    OneRtt(ProtectedOneRttHeader),
    Handshake(ProtectedHandshakeHeader),
    ZeroRTT(ProtectedZeroRTTHeader),
}

pub mod ext {
    use super::{
        long::{ext::WriteLongHeader, LongHeaderWrapper},
        short::ext::WriteOneRttHeader,
        BeProtected, PlainHeaderWrapper, Protect, ProtectedOneRttHeader,
    };
    use bytes::BufMut;

    pub trait WritePlainHeader<T: BeProtected> {
        fn write_plain_header(&mut self, header: &PlainHeaderWrapper<T>);
    }

    impl<T, S> WritePlainHeader<LongHeaderWrapper<S>> for T
    where
        T: BufMut + WriteLongHeader<S>,
        S: Protect,
    {
        fn write_plain_header(&mut self, header: &PlainHeaderWrapper<LongHeaderWrapper<S>>) {
            self.write_long_header(&header.0)
        }
    }

    impl<T> WritePlainHeader<ProtectedOneRttHeader> for T
    where
        T: BufMut + WriteOneRttHeader,
    {
        fn write_plain_header(&mut self, header: &PlainHeaderWrapper<ProtectedOneRttHeader>) {
            self.put_one_rtt_header(&header.0)
        }
    }
}
