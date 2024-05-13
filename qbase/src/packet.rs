use crate::{
    cid::{be_connection_id, ConnectionId},
    error::{Error as QuicError, ErrorKind},
};
use bytes::{Bytes, BytesMut};
use deref_derive::{Deref, DerefMut};
use enum_dispatch::enum_dispatch;
use rustls::quic::DirectionalKeys;
use thiserror::Error;

pub mod signal;
pub use signal::{KeyPhaseToggle, SpinToggle};

pub mod header;
pub use header::{
    LongHeaderBuilder, PlainHandshakeHeader, PlainInitialHeader, PlainOneRttHeader,
    PlainZeroRTTHeader, ProtectedHandshakeHeader, ProtectedHeader, ProtectedInitialHeader,
    ProtectedOneRttHeader, ProtectedZeroRTTHeader, RetryHeader, VersionNegotiationHeader,
};

pub mod number;
pub use number::{take_pn_len, PacketNumber, WritePacketNumber};

#[enum_dispatch]
pub trait GetDcid {
    fn get_dcid(&self) -> &ConnectionId;
}

#[enum_dispatch]
pub trait DecryptPacket {
    fn decrypt_packet(
        self,
        expected_pn: u64,
        remote_keys: &DirectionalKeys,
    ) -> Result<(u64, Bytes), QuicError>;
}

#[derive(Debug, Clone, Deref, DerefMut)]
pub struct ProtectedPacketWrapper<H> {
    #[deref]
    pub header: H,
    pub raw_data: BytesMut,
    pub pn_offset: usize,
}

impl<H: header::GetVersion> header::GetVersion for ProtectedPacketWrapper<H> {
    fn get_version(&self) -> u32 {
        self.header.get_version()
    }
}

impl<H: GetDcid> GetDcid for ProtectedPacketWrapper<H> {
    fn get_dcid(&self) -> &ConnectionId {
        self.header.get_dcid()
    }
}

impl<H> DecryptPacket for ProtectedPacketWrapper<H>
where
    H: header::BeProtected + header::RemoveProtection,
{
    fn decrypt_packet(
        mut self,
        expected_pn: u64,
        remote_keys: &DirectionalKeys,
    ) -> Result<(u64, Bytes), QuicError> {
        let mut packet_type = self.header.cipher_packet_type();
        let (_, payload) = self.raw_data.split_at_mut(self.pn_offset);
        let (pn_bytes, sample) = payload.split_at_mut(4);
        remote_keys
            .header
            .decrypt_in_place(sample, &mut packet_type, pn_bytes)
            .map_err(|e| {
                QuicError::new_with_default_fty(
                    ErrorKind::Crypto(rustls::AlertDescription::DecryptError.get_u8()),
                    format!("decrypt header of packet type {} error: {}", packet_type, e),
                )
            })?;

        let pn_len = self.header.remove_protection(packet_type)?;
        let header_offset = self.pn_offset + pn_len as usize;
        let pn_bytes = &payload[self.pn_offset..header_offset];
        let (_, pn) = take_pn_len(pn_len)(pn_bytes).unwrap();

        let mut raw_data = self.raw_data;
        raw_data[0] = packet_type;
        let mut body = raw_data.split_off(header_offset);
        let header = raw_data.freeze();
        let pn = pn.decode(expected_pn);
        remote_keys
            .packet
            .decrypt_in_place(pn, &header, &mut body)
            .map_err(|e| {
                QuicError::new_with_default_fty(
                    ErrorKind::Crypto(rustls::AlertDescription::DecryptError.get_u8()),
                    format!("decrypt packet({}) error: {}", packet_type, e),
                )
            })?;
        Ok((pn, body.freeze()))
    }
}

pub type ProtectedInitialPacket = ProtectedPacketWrapper<ProtectedInitialHeader>;
pub type ProtectedHandshakePacket = ProtectedPacketWrapper<ProtectedHandshakeHeader>;
pub type ProtectedZeroRttPacket = ProtectedPacketWrapper<ProtectedZeroRTTHeader>;
pub type ProtectedOneRttPacket = ProtectedPacketWrapper<ProtectedOneRttHeader>;

#[derive(Debug, Clone)]
#[enum_dispatch(DecryptPacket, GetDcid)]
pub enum ProtectedPacket {
    Initial(ProtectedInitialPacket),
    Handshake(ProtectedHandshakePacket),
    ZeroRtt(ProtectedZeroRttPacket),
    OneRtt(ProtectedOneRttPacket),
}

#[derive(Debug, Clone)]
pub enum Packet {
    VersionNegotiation(VersionNegotiationHeader),
    Retry(RetryHeader),
    Protected(ProtectedPacket),
}

#[derive(Debug, Clone, Error)]
#[error("parse packet error")]
pub struct ParsePacketError;

pub mod ext {
    use super::*;
    use bytes::BytesMut;
    use nom::{
        bytes::streaming::take,
        combinator::eof,
        multi::many_till,
        number::streaming::{be_u32, be_u8},
        Err,
    };
    use rustls::quic::DirectionalKeys;

    pub(super) fn complete<H>(
        header: H,
        mut raw_data: BytesMut,
        remain: &[u8],
    ) -> nom::IResult<&[u8], ProtectedPacketWrapper<H>>
    where
        H: header::BeProtected + header::RemoveProtection + header::GetLength,
    {
        let pn_offset = raw_data.len() - remain.len();
        let length = header.get_length();
        let packet_length = pn_offset + length;
        if length < 20 {
            return Err(nom::Err::Incomplete(nom::Needed::new(20)));
        }
        if length > remain.len() {
            return Err(nom::Err::Incomplete(nom::Needed::new(length)));
        }
        raw_data.truncate(packet_length);
        Ok((
            &remain[length..],
            ProtectedPacketWrapper {
                header,
                raw_data,
                pn_offset,
            },
        ))
    }

    pub fn be_packet(
        datagram: BytesMut,
        dcid_len: usize,
    ) -> impl FnMut(&[u8]) -> nom::IResult<&[u8], Packet> {
        move |input| {
            let mut raw_data = datagram.clone();
            let start = raw_data.len() - input.len();
            let _ = raw_data.split_to(start);
            let (remain, ty) = be_u8(input)?;
            if ty & header::HEADER_FORM_MASK == header::LONG_HEADER_BIT {
                // long header
                let (remain, version) = be_u32(remain)?;
                let (remain, scid) = be_connection_id(remain)?;
                let (remain, dcid) = be_connection_id(remain)?;
                let builder = header::LongHeaderBuilder {
                    ty,
                    version,
                    dcid,
                    scid,
                };
                builder.parse(ty, remain, raw_data)
            } else {
                // short header
                let (remain, dcid) = take(dcid_len)(remain)?;
                if remain.len() < 20 {
                    return Err(Err::Incomplete(nom::Needed::new(20)));
                }
                let header = ProtectedOneRttHeader {
                    ty,
                    dcid: ConnectionId::from_slice(dcid),
                };
                let pn_offset = raw_data.len() - remain.len();
                Ok((
                    remain,
                    Packet::Protected(ProtectedPacket::OneRtt(ProtectedOneRttPacket {
                        header,
                        raw_data,
                        pn_offset,
                    })),
                ))
            }
        }
    }

    /// 此处解析并不涉及去除头部保护、解密数据包的部分，只是解析出包类型、连接ID等信息，
    /// 找到连接ID为进一步向连接交付做准备，去除头部保护、解密数据包的部分则在连接层进行.
    /// 收到的一个数据包是BytesMut，是为了做尽量少的Copy，直到应用层读走
    pub fn parse_packet_from_datagram(datagram: BytesMut) -> Result<Vec<Packet>, ParsePacketError> {
        let raw = datagram.clone();
        let input = datagram.as_ref();
        let (_, (packets, _)) =
            many_till(be_packet(raw, 16), eof)(input).map_err(|_ne| ParsePacketError)?;
        Ok(packets)
    }

    pub fn encrypy_packet(
        packet: &mut [u8],
        pn: u64,
        pn_offset: usize,
        header_offset: usize,
        local_keys: &DirectionalKeys,
    ) {
        let (header, body) = packet.split_at_mut(header_offset);
        local_keys
            .packet
            .encrypt_in_place(pn, header, body)
            .unwrap();

        let (header, payload) = packet.split_at_mut(pn_offset);
        let first_byte = &mut header[0];
        let (pn_bytes, sample) = payload.split_at_mut(4);
        let pn_bytes = &mut pn_bytes[..header_offset - pn_offset];
        local_keys
            .header
            .encrypt_in_place(sample, first_byte, pn_bytes)
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::RetryHeader;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);

        let retry_packet = RetryHeader::default();
        let token = &retry_packet.token;
        println!("{:?}", token);
    }
}
