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
    use super::{GetType, OneRttHeader};
    use crate::packet::{r#type::ext::WritePacketType, signal::SpinBit};
    use bytes::BufMut;

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
