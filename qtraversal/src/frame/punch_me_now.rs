use std::net::SocketAddr;

use derive_more::Deref;
use qbase::{
    frame::EncodeSize,
    net::{
        AddrFamily, Family, be_socket_addr,
        route::{WriteLink, be_link},
    },
    varint::{VarInt, WriteVarInt, be_varint},
};

use super::{
    GetFrameType,
    io::{self},
};
use crate::{
    Link,
    frame::{PUNCH_ME_NOW_FRAME_TYPE, PunchPair},
    nat::client::NatType,
};

/// PUNCH_ME_NOW Frame
///
///```text
/// PUNCH_ME_NOW Frame {
///     Type (i) = 0x3d7e92,0x3d7e93
///     Link (),
///     Paired With Sequence Number (i),
///     [ IPv4 (32) ],
///     [ IPv6 (128) ],
///     Port (16),
///     Tire (i),
///     Nat type (i),
/// }
/// ```

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deref)]
pub struct PunchMeNowFrame {
    link: Link,
    paired_with_seq_num: VarInt,
    #[deref]
    address: SocketAddr,
    tire: VarInt,
    nat_type: VarInt,
}

impl PunchPair for PunchMeNowFrame {
    fn punch_pair(&self) -> Option<Link> {
        Some(self.link)
    }
}

pub fn be_punch_me_now_frame(
    family: Family,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], PunchMeNowFrame> {
    move |input| {
        let (remain, link) = be_link(input)?;
        let (remain, paired_with_seq_num) = be_varint(remain)?;
        let (remain, address) = be_socket_addr(remain, family)?;
        let (remain, tire) = be_varint(remain)?;
        let (remain, nat_type) = be_varint(remain)?;
        Ok((
            remain,
            PunchMeNowFrame {
                link,
                paired_with_seq_num,
                address,
                tire,
                nat_type,
            },
        ))
    }
}

impl GetFrameType for PunchMeNowFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PunchMeNow(self.address.family())
    }
}

impl EncodeSize for PunchMeNowFrame {
    fn max_encoding_size(&self) -> usize {
        self.typ().encoding_size()
            + self.link.max_encoding_size()
            + self.paired_with_seq_num.encoding_size()
            + self.address.max_encoding_size()
            + self.tire.encoding_size()
            + self.nat_type.encoding_size()
    }

    fn encoding_size(&self) -> usize {
        self.typ().encoding_size()
            + self.link.encoding_size()
            + self.paired_with_seq_num.encoding_size()
            + self.address.encoding_size()
            + self.tire.encoding_size()
            + self.nat_type.encoding_size()
    }
}

impl PunchMeNowFrame {
    pub fn new(
        punch_pair: Link,
        paired_with_seq_num: u32,
        address: SocketAddr,
        tire: u32,
        nat_type: NatType,
    ) -> Self {
        Self {
            link: punch_pair,
            paired_with_seq_num: VarInt::from_u32(paired_with_seq_num),
            address,
            tire: VarInt::from_u32(tire),
            nat_type: nat_type.into(),
        }
    }

    fn typ(&self) -> VarInt {
        let mut typ = PUNCH_ME_NOW_FRAME_TYPE;
        typ |= self.address.ip().is_ipv6() as u32;
        VarInt::from_u32(typ)
    }

    pub fn paired_with_seq_num(&self) -> u32 {
        self.paired_with_seq_num.into_inner() as u32
    }

    pub fn nat_type(&self) -> NatType {
        self.nat_type.try_into().unwrap()
    }

    pub fn set_addr(&mut self, addr: SocketAddr) {
        self.address = addr;
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn tire(&self) -> u32 {
        self.tire.into_inner() as u32
    }
}

impl<T: bytes::BufMut> io::WriteFrame<PunchMeNowFrame> for T {
    fn put_frame(&mut self, frame: &PunchMeNowFrame) {
        let typ = frame.typ();
        self.put_varint(&typ);
        self.put_link(&frame.link);
        self.put_varint(&frame.paired_with_seq_num);
        self.put_u16(frame.address.port());
        match frame.address.ip() {
            std::net::IpAddr::V4(ipv4) => self.put_slice(&ipv4.octets()),
            std::net::IpAddr::V6(ipv6) => self.put_slice(&ipv6.octets()),
        }
        self.put_varint(&frame.tire);
        self.put_varint(&frame.nat_type);
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::{Link, frame::io::WriteFrame};

    #[test]
    fn test_punch_me_now_frame() {
        let frame = PunchMeNowFrame {
            link: Link::new(
                "127.0.0.1:12345".parse().unwrap(),
                "127.0.0.1:54321".parse().unwrap(),
            ),
            paired_with_seq_num: VarInt::from_u32(0x01u32),
            address: "127.0.0.1:12345".parse().unwrap(),
            tire: VarInt::from_u32(0x01u32),
            nat_type: VarInt::from_u32(0x01u32),
        };
        let mut buf = BytesMut::with_capacity(frame.max_encoding_size());
        buf.put_frame(&frame);
        let (remain, typ) = be_varint(&buf).unwrap();
        assert_eq!(typ, VarInt::from_u32(PUNCH_ME_NOW_FRAME_TYPE));
        let frame2 = be_punch_me_now_frame(Family::V4)(remain).unwrap().1;
        assert_eq!(frame, frame2);
    }
}
