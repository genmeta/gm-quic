use bytes::BytesMut;
use nom::{Parser, multi::length_data};

use super::{
    error::Error,
    header::io::be_header,
    r#type::{Type, io::be_packet_type},
    *,
};
use crate::varint::be_varint;

/// Parse the payload of a packet.
///
/// - For long packets, the payload is a [`nom::multi::length_data`].
/// - For 1-RTT packet, the payload is the remaining content of the datagram.
fn be_payload(
    pkty: Type,
    datagram: &mut BytesMut,
    remain_len: usize,
) -> Result<(BytesMut, usize), Error> {
    let offset = datagram.len() - remain_len;
    let input = &datagram[offset..];
    let (remain, payload) = length_data(be_varint).parse(input).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => Error::IncompleteHeader(pkty, ne.to_string()),
        _ => unreachable!("parsing packet header never generates error or failure"),
    })?;
    let payload_len = payload.len();
    if payload_len < 20 {
        // The payload needs at least 20 bytes to have enough samples to remove the packet header protection.
        tracing::error!("   Cause by: parsing {:?} packet", pkty);
        return Err(Error::UnderSampling(payload.len()));
    }
    let packet_length = datagram.len() - remain.len();
    let bytes = datagram.split_to(packet_length);
    Ok((bytes, packet_length - payload_len))
}

/// Parse the QUIC packet from the datagram, given the length of the DCID.
/// Returns the parsed packet or an error, and the datagram removed the packet's content.
pub fn be_packet(datagram: &mut BytesMut, dcid_len: usize) -> Result<Packet, Error> {
    let input = datagram.as_ref();
    let (remain, pkty) = be_packet_type(input).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => Error::IncompleteType(ne.to_string()),
        nom::Err::Error(e) => e,
        _ => unreachable!("parsing packet type never generates failure"),
    })?;
    let (remain, header) = be_header(pkty, dcid_len, remain).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => Error::IncompleteHeader(pkty, ne.to_string()),
        _ => unreachable!("parsing packet header never generates error or failure"),
    })?;
    match header {
        Header::VN(header) => {
            datagram.clear();
            Ok(Packet::VN(header))
        }
        Header::Retry(header) => {
            datagram.clear();
            Ok(Packet::Retry(header))
        }
        Header::Initial(header) => {
            let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Long(long::DataHeader::Initial(header)),
                bytes,
                offset,
            }))
        }
        Header::ZeroRtt(header) => {
            let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Long(long::DataHeader::ZeroRtt(header)),
                bytes,
                offset,
            }))
        }
        Header::Handshake(header) => {
            let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Long(long::DataHeader::Handshake(header)),
                bytes,
                offset,
            }))
        }
        Header::OneRtt(header) => {
            if remain.len() < 20 {
                // The payload needs at least 20 bytes to have enough samples to remove the packet header protection.
                tracing::error!("   Cause by: parsing 1-RTT packet");
                return Err(Error::UnderSampling(remain.len()));
            }
            let bytes = datagram.clone();
            let offset = bytes.len() - remain.len();
            datagram.clear();
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Short(header),
                bytes,
                offset,
            }))
        }
    }
}

#[derive(CopyGetters)]
pub struct PacketLayout {
    hdr_len: usize,
    len_encoding: usize,
    pn: (u64, PacketNumber),

    cursor: usize,
    end: usize,

    // keys, can also be used to indicates whether the packet is long header or short header
    keys: Keys,

    // Packets containing only frames with [`Spec::N`] are not ack-eliciting;
    // otherwise, they are ack-eliciting.
    #[getset(get_copy = "pub")]
    ack_eliciting: bool,
    // A Boolean that indicates whether the packet counts toward bytes in flight.
    // See [Section 2](https://www.rfc-editor.org/rfc/rfc9002#section-2)
    // and [Appendix A.1](https://www.rfc-editor.org/rfc/rfc9002#section-a.1)
    // of [QUIC Recovery](https://www.rfc-editor.org/rfc/rfc9002).
    //
    // Packets containing only frames with [`Spec::C`] do not
    // count toward bytes in flight for congestion control purposes.
    #[getset(get_copy = "pub")]
    in_flight: bool,
    // Packets containing only frames with [`Spec::P`] can be used to
    // probe new network paths during connection migration.
    #[getset(get_copy = "pub")]
    probe_new_path: bool,
}

impl PacketLayout {
    pub fn writer(mut self, buffer: &mut [u8]) -> PacketWriter {
        self.end = buffer.len() - self.keys.pk().tag_len();
        assert!(self.end >= self.cursor);
        PacketWriter {
            layout: self,
            buffer,
        }
    }

    pub fn payload_len(&self) -> usize {
        self.cursor - self.hdr_len - self.len_encoding
    }

    pub fn tag_len(&self) -> usize {
        self.keys.pk().tag_len()
    }

    pub fn packet_len(&self) -> usize {
        self.cursor + self.tag_len()
    }

    pub fn is_short_header(&self) -> bool {
        self.keys.key_phase().is_some()
    }

    pub fn add_frame(&mut self, frame: &impl FrameFeture) {
        self.ack_eliciting |= !frame.specs().contain(Spec::NonAckEliciting);
        self.in_flight |= !frame.specs().contain(Spec::CongestionControlFree);
        self.probe_new_path |= frame.specs().contain(Spec::ProbeNewPath);
    }
}

#[derive(Deref, DerefMut)]
pub struct PacketWriter<'b> {
    #[deref]
    #[deref_mut]
    layout: PacketLayout,
    buffer: &'b mut [u8],
}

impl<'b> PacketWriter<'b> {
    pub fn new_long<S>(
        header: &LongHeader<S>,
        buffer: &'b mut [u8],
        pn: (u64, PacketNumber),
        keys: Arc<rustls::quic::Keys>,
    ) -> Result<Self, Signals>
    where
        S: EncodeHeader,
        for<'a> &'a mut [u8]: WriteHeader<LongHeader<S>>,
    {
        let hdr_len = header.size();
        let len_encoding = header.length_encoding();
        if buffer.len() < hdr_len + len_encoding + 20 {
            return Err(Signals::CONGESTION);
        }

        let (mut hdr_buf, mut payload_buf) = buffer.split_at_mut(hdr_len + len_encoding);
        let encoded_pn = pn.1;
        hdr_buf.put_header(header);
        payload_buf.put_packet_number(encoded_pn);

        let cursor = hdr_len + len_encoding + encoded_pn.size();
        let keys = Keys::LongHeaderPacket { keys };
        let end = buffer.len() - keys.pk().tag_len();
        let layout = PacketLayout {
            hdr_len,
            len_encoding,
            pn,
            cursor,
            end,
            keys,
            ack_eliciting: false,
            in_flight: false,
            probe_new_path: false,
        };
        Ok(Self { buffer, layout })
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer[..self.layout.packet_len()]
    }

    pub fn new_short(
        header: &OneRttHeader,
        buffer: &'b mut [u8],
        pn: (u64, PacketNumber),
        hpk: Arc<dyn rustls::quic::HeaderProtectionKey>,
        pk: Arc<dyn rustls::quic::PacketKey>,
        key_phase: KeyPhaseBit,
    ) -> Result<Self, Signals> {
        let hdr_len = header.size();
        if buffer.len() < hdr_len + 20 {
            return Err(Signals::CONGESTION);
        }

        let (mut hdr_buf, mut payload_buf) = buffer.split_at_mut(hdr_len);
        let encoded_pn = pn.1;
        hdr_buf.put_header(header);
        payload_buf.put_packet_number(encoded_pn);
        let cursor = hdr_len + encoded_pn.size();
        let keys = Keys::ShortHeaderPacket { hpk, pk, key_phase };
        let end = buffer.len() - keys.pk().tag_len();
        let packet = PacketLayout {
            hdr_len,
            len_encoding: 0,
            pn,
            cursor,
            end,
            keys,
            ack_eliciting: false,
            in_flight: false,
            probe_new_path: false,
        };
        Ok(Self {
            buffer,
            layout: packet,
        })
    }

    pub fn interrupt(self) -> (PacketLayout, &'b mut [u8]) {
        (self.layout, self.buffer)
    }

    pub fn pad(&mut self, cnt: usize) {
        self.put_bytes(0, cnt);
    }

    #[inline]
    pub fn is_ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }

    #[inline]
    pub fn in_flight(&self) -> bool {
        self.in_flight
    }

    pub fn is_empty(&self) -> bool {
        self.cursor == self.hdr_len + self.len_encoding + self.pn.1.size()
    }

    pub fn encrypt_and_protect(self) -> FinalPacketLayout {
        let (packet, buffer) = (self.layout, self.buffer);
        let payload_len = packet.payload_len();
        let tag_len = packet.keys.pk().tag_len();

        let (actual_pn, encoded_pn) = packet.pn;
        let pn_len = encoded_pn.size();
        let pkt_size = packet.cursor + tag_len;

        assert!(
            payload_len + tag_len >= 20,
            "The payload needs at least 20 bytes to have enough samples to remove the packet header protection."
        );

        if packet.is_short_header() {
            let key_phase = packet.keys.key_phase().unwrap();
            encode_short_first_byte(&mut buffer[0], pn_len, key_phase);

            let pk = packet.keys.pk();
            let payload_offset = packet.hdr_len;
            let body_offset = payload_offset + pn_len;
            encrypt_packet(pk, actual_pn, &mut buffer[..pkt_size], body_offset);

            let hpk = packet.keys.hpk();
            protect_header(hpk, &mut buffer[..pkt_size], payload_offset, pn_len);
        } else {
            let packet_len = payload_len + tag_len;
            let len_buffer_range = packet.hdr_len..packet.hdr_len + packet.len_encoding;
            let mut len_buf = &mut buffer[len_buffer_range];
            len_buf.encode_varint(&VarInt::try_from(packet_len).unwrap(), EncodeBytes::Two);

            encode_long_first_byte(&mut buffer[0], pn_len);

            let pk = packet.keys.pk();
            let payload_offset = packet.hdr_len + packet.len_encoding;
            let body_offset = payload_offset + pn_len;
            encrypt_packet(pk, actual_pn, &mut buffer[..pkt_size], body_offset);

            let hpk = packet.keys.hpk();
            protect_header(hpk, &mut buffer[..pkt_size], payload_offset, pn_len);
        }
        FinalPacketLayout {
            pn: actual_pn,
            sent_bytes: pkt_size,
            is_ack_eliciting: packet.ack_eliciting,
            in_flight: packet.in_flight,
        }
    }
}

#[derive(Debug, CopyGetters, Clone, Copy)]
pub struct FinalPacketLayout {
    #[getset(get_copy = "pub")]
    pn: u64,
    #[getset(get_copy = "pub")]
    sent_bytes: usize,
    #[getset(get_copy = "pub")]
    is_ack_eliciting: bool,
    #[getset(get_copy = "pub")]
    in_flight: bool,
}

impl<F> MarshalFrame<F> for PacketWriter<'_>
where
    F: FrameFeture,
    Self: WriteFrame<F>,
{
    fn dump_frame(&mut self, frame: F) -> Option<F> {
        self.add_frame(&frame);
        self.put_frame(&frame);
        Some(frame)
    }
}

impl<F, D> MarshalDataFrame<F, D> for PacketWriter<'_>
where
    D: DescribeData,
    Self: WriteData<D> + WriteDataFrame<F, D>,
{
    fn dump_frame_with_data(&mut self, frame: F, data: D) -> Option<F> {
        self.ack_eliciting = true;
        self.in_flight = true;
        self.put_data_frame(&frame, &data);
        Some(frame)
    }
}

unsafe impl BufMut for PacketWriter<'_> {
    fn remaining_mut(&self) -> usize {
        self.end - self.cursor
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        if self.remaining_mut() < cnt {
            panic!(
                "advance out of bounds: the len is {} but advancing by {}",
                cnt,
                self.remaining_mut()
            );
        }

        self.cursor += cnt;
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let range = self.cursor..self.end;
        UninitSlice::new(&mut self.buffer[range])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::CryptoFrame;

    struct TransparentKeys;

    impl rustls::quic::PacketKey for TransparentKeys {
        fn decrypt_in_place<'a>(
            &self,
            _packet_number: u64,
            _header: &[u8],
            payload: &'a mut [u8],
        ) -> Result<&'a [u8], rustls::Error> {
            Ok(&payload[..payload.len() - self.tag_len()])
        }

        fn encrypt_in_place(
            &self,
            _packet_number: u64,
            _header: &[u8],
            _payload: &mut [u8],
        ) -> Result<rustls::quic::Tag, rustls::Error> {
            Ok(rustls::quic::Tag::from("transparent_keys".as_bytes()))
        }

        fn confidentiality_limit(&self) -> u64 {
            0
        }

        fn integrity_limit(&self) -> u64 {
            0
        }

        fn tag_len(&self) -> usize {
            16
        }
    }

    impl rustls::quic::HeaderProtectionKey for TransparentKeys {
        fn decrypt_in_place(
            &self,
            _sample: &[u8],
            _first_byte: &mut u8,
            _payload: &mut [u8],
        ) -> Result<(), rustls::Error> {
            Ok(())
        }

        fn encrypt_in_place(
            &self,
            _sample: &[u8],
            _first_byte: &mut u8,
            _payload: &mut [u8],
        ) -> Result<(), rustls::Error> {
            Ok(())
        }

        fn sample_len(&self) -> usize {
            20
        }
    }

    #[test]
    fn test_initial_packet_writer() {
        let mut buffer = vec![0u8; 128];
        let header = LongHeaderBuilder::with_cid(
            ConnectionId::from_slice("testdcid".as_bytes()),
            ConnectionId::from_slice("testscid".as_bytes()),
        )
        .initial(b"test_token".to_vec());

        let pn = (0, PacketNumber::encode(0, 0));

        let keys = Arc::new(rustls::quic::Keys {
            local: rustls::quic::DirectionalKeys {
                packet: Box::new(TransparentKeys),
                header: Box::new(TransparentKeys),
            },
            remote: rustls::quic::DirectionalKeys {
                packet: Box::new(TransparentKeys),
                header: Box::new(TransparentKeys),
            },
        });

        let mut writer = PacketWriter::new_long(&header, &mut buffer, pn, keys).unwrap();
        let frame = CryptoFrame::new(VarInt::from_u32(0), VarInt::from_u32(12));
        writer.dump_frame_with_data(frame, "client_hello".as_bytes());

        assert!(writer.is_ack_eliciting());
        assert!(writer.in_flight());

        let final_packet_layout = writer.encrypt_and_protect();
        assert!(final_packet_layout.is_ack_eliciting());
        assert!(final_packet_layout.in_flight());
        assert_eq!(final_packet_layout.sent_bytes(), 69);
        assert_eq!(
            &buffer[..final_packet_layout.sent_bytes()],
            [
                // initial packet:
                // header form (1) = 1,, long header
                // fixed bit (1) = 1,
                // long packet type (2) = 0, initial packet
                // reserved bits (2) = 0,
                // packet number length (2) = 0, 1 byte
                193, // first byte
                0, 0, 0, 1, // quic version
                // destination connection id, "testdcid"
                8, // dcid length
                b't', b'e', b's', b't', b'd', b'c', b'i', b'd', // dcid bytes
                // source connection id, "testscid"
                8, // scid length
                b't', b'e', b's', b't', b's', b'c', b'i', b'd', // scid bytes
                10,   // token length, no token
                b't', b'e', b's', b't', b'_', b't', b'o', b'k', b'e', b'n', // token bytes
                64, 33, // payload length, 2 bytes encoded varint
                0, 0, // encoded packet number
                // crypto frame header
                6,  // crypto frame type
                0,  // crypto frame offset
                12, // crypto frame length
                // crypto frame data, "client hello"
                b'c', b'l', b'i', b'e', b'n', b't', b'_', b'h', b'e', b'l', b'l', b'o',
                // tag, "transparent_keys"
                b't', b'r', b'a', b'n', b's', b'p', b'a', b'r', b'e', b'n', b't', b'_', b'k', b'e',
                b'y', b's',
            ]
            .as_slice()
        );
    }
}
