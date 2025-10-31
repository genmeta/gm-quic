use std::net::{IpAddr, SocketAddr};

use derive_more::Deref;
use qbase::{
    frame::EncodeSize,
    net::{AddrFamily, Family, WriteSocketAddr, be_socket_addr},
    varint::{VarInt, WriteVarInt, be_varint},
};

use crate::{
    Link,
    frame::{ADD_ADDRESS_FRAME_TYPE, PunchPair},
    nat::client::NatType,
};

// ADD_ADDRESS Frame {
//     Type (i) = 0x3d7e90..0x3d7e91,
//     Sequence Number (i),
//     [ IPv4 (32) ],
//     [ IPv6 (128) ],
//     Port (16),
//     Tire (i),
//     NAT Type (i),
// }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deref)]
pub struct AddAddressFrame {
    #[deref]
    address: SocketAddr,
    seq_num: VarInt,
    tire: VarInt,
    nat_type: VarInt,
}

pub(crate) fn be_add_address_frame(
    family: Family,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], AddAddressFrame> {
    move |input| {
        let (remain, seq_num) = be_varint(input)?;
        let (remain, addr) = be_socket_addr(remain, family)?;
        let (remain, tire) = be_varint(remain)?;
        let (remain, nat_type) = be_varint(remain)?;
        Ok((
            remain,
            AddAddressFrame {
                seq_num,
                address: addr,
                tire,
                nat_type,
            },
        ))
    }
}

impl super::GetFrameType for AddAddressFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::AddAddress(self.address.family())
    }
}

impl EncodeSize for AddAddressFrame {
    fn max_encoding_size(&self) -> usize {
        self.typ().encoding_size()
            + self.seq_num.encoding_size()
            + 2  // port
            + 16 // ipv6 IP
            + self.tire.encoding_size()
            + self.nat_type.encoding_size()
    }

    fn encoding_size(&self) -> usize {
        let addr_size = match self.address.ip() {
            IpAddr::V4(_) => 2 + 4,
            IpAddr::V6(_) => 2 + 16,
        };
        self.typ().encoding_size()
            + self.seq_num.encoding_size()
            + addr_size
            + self.tire.encoding_size()
            + self.nat_type.encoding_size()
    }
}

impl AddAddressFrame {
    pub fn new(seq_num: u32, address: SocketAddr, tire: u32, nat_type: u32) -> Self {
        Self {
            seq_num: VarInt::from_u32(seq_num),
            address,
            tire: VarInt::from_u32(tire),
            nat_type: VarInt::from_u32(nat_type),
        }
    }

    pub fn typ(&self) -> VarInt {
        VarInt::from_u32(ADD_ADDRESS_FRAME_TYPE | self.address.is_ipv6() as u32)
    }

    pub fn seq_num(&self) -> u32 {
        self.seq_num.into_inner() as u32
    }

    pub fn tire(&self) -> u32 {
        self.tire.into_inner() as u32
    }

    pub fn nat_type(&self) -> NatType {
        self.nat_type.try_into().unwrap()
    }
}

impl<T: bytes::BufMut> super::io::WriteFrame<AddAddressFrame> for T {
    fn put_frame(&mut self, frame: &AddAddressFrame) {
        let typ = frame.typ();
        self.put_varint(&typ);
        self.put_varint(&frame.seq_num);
        self.put_socket_addr(&frame.address);
        self.put_varint(&frame.tire);
        self.put_varint(&frame.nat_type);
    }
}

impl PunchPair for AddAddressFrame {
    fn punch_pair(&self) -> Option<Link> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::BytesMut;

    use super::*;
    use crate::frame::io::WriteFrame;

    #[test]
    fn test_add_address_frame() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let frame = AddAddressFrame {
            seq_num: VarInt::from_u32(1u32),
            address: addr,
            tire: VarInt::from_u32(1u32),
            nat_type: VarInt::from_u32(1u32),
        };
        let mut buf = BytesMut::new();
        buf.put_frame(&frame);
        let (remain, typ) = be_varint(&buf).unwrap();
        assert_eq!(typ, VarInt::from_u32(ADD_ADDRESS_FRAME_TYPE));
        let frame2 = be_add_address_frame(Family::V4)(remain).unwrap().1;
        assert_eq!(frame, frame2);
    }
}
