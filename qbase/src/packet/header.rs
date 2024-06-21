use crate::cid::ConnectionId;
use enum_dispatch::enum_dispatch;

pub mod long;
pub mod short;

pub use long::{
    ext::{LongHeaderBuilder, Write, WriteLongHeader},
    HandshakeHeader, InitialHeader, LongHeader, RetryHeader, VersionNegotiationHeader,
    ZeroRttHeader,
};
pub use short::{ext::WriteOneRttHeader, OneRttHeader};

use super::r#type::{
    long::{v1, Type as LongType, Version},
    short::OneRtt,
    Type,
};

pub trait GetType {
    fn get_type(&self) -> Type;
}

pub trait Protect {}

/// Some long packet headers such as Initial, Handshake, ZeroRtt, etc. have lengths,
/// so they need to implement this trait.
/// However, the length is variable-length encoding, and the length is unknown when
/// writing. The special handling of variable-length encoding length is left to the
/// sending logic to handle, so there is no method to set the length.
pub trait HasLength {
    fn get_length(&self) -> usize;
}

/// When encoding a packet for sending, we need to know the length of the packet,
/// so this trait needs to be implemented.
/// However, the length field of the packet header is variable-length encoded and
/// requires special handling, which is not considered within the scope of Encode::size.
pub trait Encode {
    fn size(&self) -> usize {
        0
    }
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
    fn test_read_header() {
        use super::{ext::be_header, Header};
        use crate::{
            cid::ConnectionId,
            packet::r#type::{long, long::Ver1, short::OneRtt, Type},
            packet::SpinBit,
        };

        // VersionNegotiation Header
        let buf = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
        let (remain, vn_long_header) =
            be_header(Type::Long(long::Type::VersionNegotiation), 0, &buf).unwrap();
        assert_eq!(remain.len(), 0);
        match vn_long_header {
            Header::VN(vn) => {
                assert_eq!(vn.dcid, ConnectionId::default());
                assert_eq!(vn.scid, ConnectionId::default());
                assert_eq!(vn.specific.versions, vec![0x01, 0x02]);
            }
            _ => panic!("unexpected header type"),
        }

        // Retry Header
        let buf = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let (remain, retry_long_header) =
            be_header(Type::Long(long::Type::V1(Ver1::RETRY)), 0, &buf).unwrap();
        assert_eq!(remain.len(), 0);
        match retry_long_header {
            Header::Retry(retry) => {
                assert_eq!(retry.dcid, ConnectionId::default());
                assert_eq!(retry.scid, ConnectionId::default());
                assert_eq!(retry.token, [0x00, 0x00, 0x00]);
                assert_eq!(
                    retry.integrity,
                    [
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                        0x0c, 0x0d, 0x0e, 0x0f
                    ]
                );
            }
            _ => panic!("unexpected header type"),
        }

        // Retry Header with invalid length
        let buf = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f,
        ];
        match be_header(Type::Long(long::Type::V1(Ver1::RETRY)), 0, &buf) {
            Err(e) => assert_eq!(e, nom::Err::Incomplete(nom::Needed::new(16))),
            _ => panic!("unexpected result"),
        }

        // Initial Header
        let buf = vec![0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00];
        let (remain, initial_long_header) =
            be_header(Type::Long(long::Type::V1(Ver1::INITIAL)), 0, &buf).unwrap();
        assert_eq!(remain.len(), 0);
        match initial_long_header {
            Header::Initial(initial) => {
                assert_eq!(initial.dcid, ConnectionId::default());
                assert_eq!(initial.scid, ConnectionId::default());
                assert_eq!(initial.token, [0x01, 0x02, 0x03,]);
                assert_eq!(initial.length, 0x00);
            }
            _ => panic!("unexpected header type"),
        }

        // ZeroRTT Header
        let buf = vec![0x00, 0x00, 0x00];
        let (remain, zero_rtt_long_header) =
            be_header(Type::Long(long::Type::V1(Ver1::ZERO_RTT)), 0, &buf).unwrap();
        assert_eq!(remain.len(), 0);
        match zero_rtt_long_header {
            Header::ZeroRtt(zero_rtt) => {
                assert_eq!(zero_rtt.dcid, ConnectionId::default());
                assert_eq!(zero_rtt.scid, ConnectionId::default());
                assert_eq!(zero_rtt.length, 0x00);
            }
            _ => panic!("unexpected header type"),
        }

        // Handshake Header
        let buf = vec![0x00, 0x00, 0x00];
        let (remain, handshake_long_header) =
            be_header(Type::Long(long::Type::V1(Ver1::HANDSHAKE)), 0, &buf).unwrap();
        assert_eq!(remain.len(), 0);
        match handshake_long_header {
            Header::Handshake(handshake) => {
                assert_eq!(handshake.dcid, ConnectionId::default());
                assert_eq!(handshake.scid, ConnectionId::default());
                assert_eq!(handshake.length, 0x00);
            }
            _ => panic!("unexpected header type"),
        }

        // OneRtt Header
        let buf = vec![];
        let (remain, one_rtt_header) =
            be_header(Type::Short(OneRtt(SpinBit::On)), 0, &buf).unwrap();
        assert_eq!(remain.len(), 0);
        match one_rtt_header {
            Header::OneRtt(one_rtt) => {
                assert_eq!(one_rtt.dcid, ConnectionId::default());
                assert_eq!(one_rtt.spin, SpinBit::On);
            }
            _ => panic!("unexpected header type"),
        }
    }

    #[test]
    fn test_write_header() {
        use super::{
            long::{Handshake, Initial, Retry, VersionNegotiation, ZeroRtt},
            LongHeaderBuilder,
        };
        use crate::cid::ConnectionId;
        use crate::packet::{header::ext::WriteHeader, Header};
        use crate::packet::{OneRttHeader, SpinBit};
        use crate::varint::VarInt;

        // VersionNegotiation Header
        let mut buf = vec![];
        let vn_long_header = Header::VN(
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default()).wrap(
                VersionNegotiation {
                    versions: vec![0x01, 0x02],
                },
            ),
        );
        buf.put_header(&vn_long_header);
        assert_eq!(
            buf,
            [
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x02
            ]
        );

        // Retry Header
        let mut buf = vec![];
        let retry_long_header = Header::Retry(
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default()).wrap(
                Retry {
                    token: vec![0x00, 0x00, 0x00],
                    integrity: [
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                        0x0c, 0x0d, 0x0e, 0x0f,
                    ],
                },
            ),
        );
        buf.put_header(&retry_long_header);
        assert_eq!(
            buf,
            [
                0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            ]
        );

        // Initial Header
        let mut buf = vec![];
        let initial_long_header = Header::Initial(
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default()).wrap(
                Initial {
                    length: VarInt::from_u32(0),
                    token: vec![0x01, 0x02, 0x03],
                },
            ),
        );
        buf.put_header(&initial_long_header);
        assert_eq!(
            buf,
            [0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03]
        );

        // ZeroRtt Header
        let mut buf = vec![];
        let zero_rtt_long_header = Header::ZeroRtt(
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default()).wrap(
                ZeroRtt {
                    length: VarInt::from_u32(0),
                },
            ),
        );
        buf.put_header(&zero_rtt_long_header);
        assert_eq!(buf, [0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);

        // Handshake Header
        let mut buf = vec![];
        let handshake_long_header = Header::Handshake(
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default()).wrap(
                Handshake {
                    length: VarInt::from_u32(0),
                },
            ),
        );
        buf.put_header(&handshake_long_header);
        assert_eq!(buf, [0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);

        // OneRtt Header with SpinBit::On
        let mut buf = vec![];
        let one_rtt_long_header = Header::OneRtt(OneRttHeader {
            spin: SpinBit::On,
            dcid: ConnectionId::default(),
        });
        buf.put_header(&one_rtt_long_header);
        assert_eq!(buf, [0x60]);

        // OneRtt Header with SpinBit::Off
        let mut buf = vec![];
        let one_rtt_long_header = Header::OneRtt(OneRttHeader {
            spin: SpinBit::Off,
            dcid: ConnectionId::default(),
        });
        buf.put_header(&one_rtt_long_header);
        assert_eq!(buf, [0x40]);
    }
}
