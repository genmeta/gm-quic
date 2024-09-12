use super::*;
use crate::{cid::ConnectionId, packet::SpinBit};

/// A packet with a short header does not include a length,
/// so it can only be the last packet in a UDP datagram.

/// ```text
///      +---spin bit
///      |     +---key phase bits
///      |     |
/// +----+-----+----+------+--------------+----......---+
/// |1|1|S 0 0 K 0 0| DCIL | DCID(0..160) | Payload ... |
/// +-----+---+-+---+------+--------------+----......---+
///       |<->| |<->|
///         |     |
///         |     +---> packet number length
///         +---> reserved bits, must be 0
/// ```
///
/// See [1-RTT Packet](https://www.rfc-editor.org/rfc/rfc9000.html#name-1-rtt-packet)
/// in [RFC9000](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Default, Clone)]
pub struct OneRttHeader {
    // For simplicity, the spin bit is also part of the 1RTT header.
    pub spin: SpinBit,
    pub dcid: ConnectionId,
}

impl EncodeHeader for OneRttHeader {
    fn size(&self) -> usize {
        1 + self.dcid.len()
    }
}

impl GetType for OneRttHeader {
    fn get_type(&self) -> Type {
        Type::Short(OneRtt(self.spin))
    }
}

impl super::GetDcid for OneRttHeader {
    fn get_dcid(&self) -> &ConnectionId {
        &self.dcid
    }
}

/// The io module provides functions for parsing and writing 1RTT headers.
pub mod io {
    use bytes::BufMut;

    use super::{GetType, OneRttHeader};
    use crate::packet::{r#type::io::WritePacketType, signal::SpinBit};

    /// Parse a 1RTT header from the input buffer,
    /// [nom](https://docs.rs/nom/latest/nom/) parser style.
    pub fn be_one_rtt_header(
        spin: SpinBit,
        dcid_len: usize,
        input: &[u8],
    ) -> nom::IResult<&[u8], OneRttHeader> {
        use nom::bytes::streaming::take;
        let (remain, dcid) = take(dcid_len)(input)?;
        let dcid = crate::cid::ConnectionId::from_slice(dcid);
        Ok((remain, OneRttHeader { spin, dcid }))
    }

    /// A [`bytes::BufMut`] extension trait, makes buffer more friendly to write 1RTT headers.
    pub trait WriteShortHeader: BufMut {
        /// Write a 1RTT header to the buffer.
        fn put_short_header(&mut self, header: &OneRttHeader);
    }

    impl<T: BufMut> WriteShortHeader for T {
        fn put_short_header(&mut self, header: &OneRttHeader) {
            let ty = header.get_type();
            self.put_packet_type(&ty);
            self.put_slice(&header.dcid);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::header::WriteShortHeader;

    #[test]
    fn test_read_one_rtt_header() {
        use super::io::be_one_rtt_header;
        use crate::packet::{header::ConnectionId, SpinBit};

        let (remain, header) = be_one_rtt_header(SpinBit::One, 0, &[][..]).unwrap();

        assert_eq!(remain.len(), 0);
        assert_eq!(header.spin, SpinBit::One);
        assert_eq!(header.dcid, ConnectionId::default());
    }

    #[test]
    fn test_write_one_rtt_header() {
        use super::OneRttHeader;
        use crate::{cid::ConnectionId, packet::SpinBit};

        let mut buf = vec![];
        let header = OneRttHeader {
            spin: SpinBit::One,
            dcid: ConnectionId::default(),
        };

        buf.put_short_header(&header);
        // Note: 0x60 == SHORT_HEADER_BIT | FIXED_BIT | Toggle<SPIN_BIT>.value()
        assert_eq!(buf, [0x60]);
    }
}
