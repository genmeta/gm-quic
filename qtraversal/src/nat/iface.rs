use std::{io, net::SocketAddr};

use bytes::{BufMut, BytesMut};
use qbase::net::route::{Line, Link, Route};
use qinterface::io::{IO, IoExt};

use crate::{
    nat::msg::{Packet, TransactionId, WritePacket},
    packet::{StunHeader, WriteStunHeader},
};

pub trait StunIO: IO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.bound_addr()
    }

    fn send_stun_packet(
        &self,
        packet: Packet,
        txid: TransactionId,
        dst: SocketAddr,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
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
            let link = Link::new(self.bound_addr()?, dst);
            let pathway = link.into();
            let line = Line::new(link, 64, None, 0);
            let hdr = Route::new(pathway, line);

            self.sendmmsg(bufs, hdr).await
        }
    }
}

impl<I: IO + ?Sized> StunIO for I {}
