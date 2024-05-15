use crate::cid::ConnectionId;
use enum_dispatch::enum_dispatch;

pub mod long;
pub mod short;

pub use long::{
    ext::LongHeaderBuilder, HandshakeHeader, InitialHeader, RetryHeader, VersionNegotiationHeader,
    ZeroRttHeader,
};
pub use short::OneRttHeader;

use super::r#type::{
    long::{v1, Type as LongType, Version},
    short::OneRtt,
    Type,
};

pub trait GetType {
    fn get_type(&self) -> Type;
}

pub trait Protect {}

pub trait GetLength {
    fn get_length(&self) -> usize;
}

#[enum_dispatch]
pub trait GetDcid {
    fn get_dcid(&self) -> &ConnectionId;
}

#[derive(Debug, Clone)]
#[enum_dispatch(GetDcid)]
pub enum Header {
    VN(long::VersionNegotiationHeader),
    Retry(long::RetryHeader),
    Initial(long::InitialHeader),
    ZeroRtt(long::ZeroRttHeader),
    Handshake(long::HandshakeHeader),
    OneRtt(short::OneRttHeader),
}

pub mod ext {
    use super::{
        long::{
            ext::{LongHeaderBuilder, WriteLongHeader},
            Handshake, Initial, Retry, VersionNegotiation, ZeroRtt,
        },
        short::ext::WriteOneRttHeader,
        Header,
    };
    use crate::{
        cid::be_connection_id,
        packet::{
            header::short::ext::be_one_rtt_header,
            r#type::{short::OneRtt, Type},
        },
    };

    pub fn be_header(
        packet_type: Type,
        dcid_len: usize,
        input: &[u8],
    ) -> nom::IResult<&[u8], Header> {
        match packet_type {
            Type::Long(long_ty) => {
                let (remain, dcid) = be_connection_id(input)?;
                let (remain, scid) = be_connection_id(remain)?;
                let builder = LongHeaderBuilder { dcid, scid };
                builder.parse(long_ty, remain)
            }
            Type::Short(OneRtt(spin)) => {
                let (remain, one_rtt) = be_one_rtt_header(spin, dcid_len, input)?;
                Ok((remain, Header::OneRtt(one_rtt)))
            }
        }
    }

    pub trait WriteHeader {
        fn put_header(&mut self, header: &Header);
    }

    impl<T> WriteHeader for T
    where
        T: bytes::BufMut
            + WriteLongHeader<VersionNegotiation>
            + WriteLongHeader<Retry>
            + WriteLongHeader<Initial>
            + WriteLongHeader<ZeroRtt>
            + WriteLongHeader<Handshake>
            + WriteOneRttHeader,
    {
        fn put_header(&mut self, header: &Header) {
            match header {
                Header::VN(vn) => self.put_long_header(vn),
                Header::Retry(retry) => self.put_long_header(retry),
                Header::Initial(initial) => self.put_long_header(initial),
                Header::ZeroRtt(zero_rtt) => self.put_long_header(zero_rtt),
                Header::Handshake(handshake) => self.put_long_header(handshake),
                Header::OneRtt(one_rtt) => self.put_one_rtt_header(one_rtt),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
