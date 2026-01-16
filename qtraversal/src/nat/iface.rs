use std::{io, net::SocketAddr};

use bytes::{BufMut, BytesMut};
use qbase::net::addr::RealAddr;
use qinterface::{Interface, InterfaceExt};

use crate::{
    Link,
    nat::msg::{Packet, TransactionId, WritePacket},
    packet::{StunHeader, WriteStunHeader},
};

pub trait StunIO: Interface {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        let real_addr = self.real_addr()?;
        real_addr.try_into().map_err(io::Error::other)
    }

    #[tracing::instrument(skip(self, packet, txid))]
    async fn send_stun_packet(
        &self,
        packet: Packet,
        txid: TransactionId,
        dst: SocketAddr,
    ) -> io::Result<()> {
        let mut buf = BytesMut::zeroed(128);
        let (mut stun_hdr, mut stun_body) = buf.split_at_mut(StunHeader::encoding_size());

        // put stun header
        stun_hdr.put_stun_header(&StunHeader::new(0));

        // put stun body
        let origin = stun_body.remaining_mut();
        stun_body.put_packet(&txid, &packet);
        let consumed = origin - stun_body.remaining_mut();
        buf.truncate(StunHeader::encoding_size() + consumed);

        let bufs = &[io::IoSlice::new(&buf)];

        // assemble packet header
        let link = Link::new(self.real_addr()?, RealAddr::Internet(dst));
        let pathway = link.into();

        let hdr = qbase::net::route::PacketHeader::new(pathway, link, 64, None, 0);

        self.sendmmsg(bufs, hdr).await
    }
}

impl<IO: Interface + ?Sized> StunIO for IO {}
