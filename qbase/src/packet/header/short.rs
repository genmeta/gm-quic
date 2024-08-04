use super::*;
use crate::{cid::ConnectionId, packet::SpinBit};

/// A packet with a short header does not include a length,
/// so it can only be the last packet included in a UDP datagram.
#[derive(Debug, Default, Clone)]
pub struct OneRttHeader {
    // For simplicity, the spin bit is also part of the 1RTT header.
    pub spin: SpinBit,
    pub dcid: ConnectionId,
}

impl Protect for OneRttHeader {}

impl Encode for OneRttHeader {
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

pub mod ext {
    use bytes::BufMut;

    use super::{GetType, OneRttHeader};
    use crate::packet::{r#type::ext::WritePacketType, signal::SpinBit};

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

    pub trait WriteOneRttHeader {
        fn put_one_rtt_header(&mut self, header: &OneRttHeader);
    }

    impl<T: BufMut> WriteOneRttHeader for T {
        fn put_one_rtt_header(&mut self, header: &OneRttHeader) {
            let ty = header.get_type();
            self.put_packet_type(&ty);
            // Note: Do not write the dcid's length
            self.put_slice(&header.dcid);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::header::WriteOneRttHeader;

    #[test]
    fn test_read_one_rtt_header() {
        use super::ext::be_one_rtt_header;
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

        buf.put_one_rtt_header(&header);
        // Note: 0x60 == SHORT_HEADER_BIT | FIXED_BIT | Toggle<SPIN_BIT>.value()
        assert_eq!(buf, [0x60]);
    }
}
