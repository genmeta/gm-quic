use std::net::SocketAddr;

use derive_more::Deref;

use super::{
    EncodeSize, GetFrameType,
    io::{WriteFrame, WriteFrameType},
};
use crate::{
    net::{
        AddrFamily, Family, NatType, be_socket_addr,
        route::{Link, WriteLink, be_link},
    },
    varint::{VarInt, WriteVarInt, be_varint},
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
    link: Link<SocketAddr>,
    paired_with_seq_num: VarInt,
    #[deref]
    address: SocketAddr,
    tire: VarInt,
    nat_type: NatType,
}

pub(crate) fn be_punch_me_now_frame(
    family: Family,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], PunchMeNowFrame> {
    move |input| {
        let (remain, link) = be_link(input)?;
        let (remain, paired_with_seq_num) = be_varint(remain)?;
        let (remain, address) = be_socket_addr(remain, family)?;
        let (remain, tire) = be_varint(remain)?;
        let (remain, nat_type) = be_varint(remain)?;
        let nat_type = NatType::try_from(nat_type).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(
                remain,
                nom::error::ErrorKind::Verify,
            ))
        })?;
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
        4 + self.link.max_encoding_size() + 8 + self.address.max_encoding_size() + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        VarInt::from(self.frame_type()).encoding_size()
            + self.link.encoding_size()
            + self.paired_with_seq_num.encoding_size()
            + self.address.encoding_size()
            + self.tire.encoding_size()
            + VarInt::from(self.nat_type).encoding_size()
    }
}

impl PunchMeNowFrame {
    pub fn new(
        punch_pair: Link<SocketAddr>,
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
            nat_type,
        }
    }

    pub fn paired_with_seq_num(&self) -> u32 {
        self.paired_with_seq_num.into_inner() as u32
    }

    pub fn link(&self) -> Link<SocketAddr> {
        self.link
    }

    pub fn nat_type(&self) -> NatType {
        self.nat_type
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

impl<T: bytes::BufMut> WriteFrame<PunchMeNowFrame> for T {
    fn put_frame(&mut self, frame: &PunchMeNowFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_link(&frame.link);
        self.put_varint(&frame.paired_with_seq_num);
        self.put_u16(frame.address.port());
        match frame.address.ip() {
            std::net::IpAddr::V4(ipv4) => self.put_slice(&ipv4.octets()),
            std::net::IpAddr::V6(ipv6) => self.put_slice(&ipv6.octets()),
        }
        self.put_varint(&frame.tire);
        self.put_varint(&VarInt::from(frame.nat_type));
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::frame::{GetFrameType, be_frame_type, io::WriteFrame};

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
            nat_type: NatType::FullCone,
        };
        let mut buf = BytesMut::with_capacity(frame.max_encoding_size());
        buf.put_frame(&frame);
        let (remain, frame_type) = be_frame_type(&buf).unwrap();
        assert_eq!(frame_type, frame.frame_type());
        let frame2 = be_punch_me_now_frame(Family::V4)(remain).unwrap().1;
        assert_eq!(frame, frame2);
    }
}
