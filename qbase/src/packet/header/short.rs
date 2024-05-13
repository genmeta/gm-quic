use super::{BePlain, PlainHeaderWrapper};
use crate::{
    cid::ConnectionId,
    error::{Error as QuicError, ErrorKind},
    packet::{KeyPhaseToggle, SpinToggle},
};

/// A packet with a short header does not include a length,
/// so it can only be the last packet included in a UDP datagram.
#[derive(Debug, Default, Clone)]
pub struct ProtectedOneRttHeader {
    pub ty: u8,
    pub dcid: ConnectionId,
}

impl super::BeProtected for ProtectedOneRttHeader {
    fn cipher_packet_type(&self) -> u8 {
        self.ty
    }
}

impl super::GetDcid for ProtectedOneRttHeader {
    fn get_dcid(&self) -> &ConnectionId {
        &self.dcid
    }
}

impl super::RemoveProtection for ProtectedOneRttHeader {
    fn remove_protection(mut self, plain_packet_type: u8) -> Result<u8, QuicError> {
        self.ty = plain_packet_type;
        let plain_header = super::PlainHeaderWrapper(self);
        plain_header.pn_len()
    }
}

pub type PlainOneRttHeader = PlainHeaderWrapper<ProtectedOneRttHeader>;

impl super::BePlain for PlainOneRttHeader {
    fn pn_len(&self) -> Result<u8, QuicError> {
        const RESERVED_MASK: u8 = 0x18;
        let reserved_bit = self.ty & RESERVED_MASK;
        if reserved_bit == 0 {
            Ok((self.ty & super::PN_LEN_MASK) + 1)
        } else {
            Err(QuicError::new_with_default_fty(
                ErrorKind::ProtocolViolation,
                format!("invalid reserved bits {reserved_bit}"),
            ))
        }
    }
}

impl PlainOneRttHeader {
    pub fn new(dcid: ConnectionId, spin: SpinToggle, key_phase: KeyPhaseToggle) -> Self {
        Self(ProtectedOneRttHeader {
            ty: super::SHORT_HEADER_BIT | super::FIXED_BIT | spin.value() | key_phase.value(),
            dcid,
        })
    }
}

pub mod ext {
    use super::ProtectedOneRttHeader;
    use crate::cid::WriteConnectionId;
    use bytes::BufMut;

    pub trait WriteOneRttHeader {
        fn put_one_rtt_header(&mut self, header: &ProtectedOneRttHeader);
    }

    impl<T: BufMut> WriteOneRttHeader for T {
        fn put_one_rtt_header(&mut self, header: &ProtectedOneRttHeader) {
            self.put_u8(header.ty);
            self.put_connection_id(&header.dcid);
        }
    }
}
