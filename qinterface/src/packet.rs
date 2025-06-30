use bytes::{Bytes, BytesMut};
use derive_more::Deref;
use qbase::{
    error::QuicError,
    packet::{
        decrypt::{
            decrypt_packet, remove_protection_of_long_packet, remove_protection_of_short_packet,
        },
        header::long::InitialHeader,
        keys::ArcOneRttPacketKeys,
        number::{InvalidPacketNumber, PacketNumber},
    },
};
use qevent::quic::{
    PacketHeader, PacketHeaderBuilder, QuicFrame,
    transport::{PacketDropped, PacketDroppedTrigger, PacketReceived},
};
use rustls::quic::{HeaderProtectionKey, PacketKey};

#[derive(Deref)]
pub struct CipherPacket<H> {
    #[deref]
    header: H,
    payload: BytesMut,
    payload_offset: usize,
}

impl<H> CipherPacket<H>
where
    PacketHeaderBuilder: for<'a> From<&'a H>,
{
    pub(crate) fn new(header: H, payload: BytesMut, payload_offset: usize) -> Self {
        Self {
            header,
            payload,
            payload_offset,
        }
    }

    pub fn header(&self) -> &H {
        &self.header
    }

    fn qlog_header(&self) -> PacketHeader {
        PacketHeaderBuilder::from(&self.header).build()
    }

    pub fn drop_on_key_unavailable(self) {
        qevent::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.payload.freeze(),
            trigger: PacketDroppedTrigger::KeyUnavailable
        })
    }

    fn drop_on_remove_header_protection_failure(self) {
        qevent::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.payload.freeze(),
            details: Map {
                reason: "remove header protection failure",
            },
            trigger: PacketDroppedTrigger::DecryptionFailure
        })
    }

    fn drop_on_decryption_failure(self, error: qbase::packet::error::Error, pn: u64) {
        qevent::event!(PacketDropped {
            header: {
                PacketHeaderBuilder::from(&self.header)
                    .packet_number(pn)
                    .build()
            },
            raw: self.payload.freeze(),
            details: Map {
                reason: "decryption failure",
                error: error.to_string(),
            },
            trigger: PacketDroppedTrigger::DecryptionFailure
        })
    }

    fn drop_on_reverse_bit_error(self, error: &qbase::packet::error::Error) {
        qevent::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.payload.freeze(),
            details: Map {
                reason: "reverse bit error",
                error: error.to_string()
            },
            trigger: PacketDroppedTrigger::Invalid,
        })
    }

    fn drop_on_invalid_pn(self, invalid_pn: InvalidPacketNumber) {
        qevent::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.payload.freeze(),
            details: Map {
                reason: "invalid packet number",
                invalid_pn: invalid_pn.to_string()
            },
            trigger: PacketDroppedTrigger::Invalid,
        })
    }

    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub fn decrypt_long_packet(
        mut self,
        hpk: &dyn HeaderProtectionKey,
        pk: &dyn PacketKey,
        pn_decoder: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
    ) -> Option<Result<PlainPacket<H>, QuicError>> {
        let pkt_buf = self.payload.as_mut();
        let undecoded_pn = match remove_protection_of_long_packet(hpk, pkt_buf, self.payload_offset)
        {
            Ok(Some(undecoded_pn)) => undecoded_pn,
            Ok(None) => {
                self.drop_on_remove_header_protection_failure();
                return None;
            }
            Err(invalid_reverse_bits) => {
                self.drop_on_reverse_bit_error(&invalid_reverse_bits);
                return Some(Err(invalid_reverse_bits.into()));
            }
        };
        let decoded_pn = match pn_decoder(undecoded_pn) {
            Ok(pn) => pn,
            Err(invalid_packet_number) => {
                tracing::error!(?invalid_packet_number, "Error:");
                self.drop_on_invalid_pn(invalid_packet_number);
                return None;
            }
        };
        let body_offset = self.payload_offset + undecoded_pn.size();
        let body_length = match decrypt_packet(pk, decoded_pn, pkt_buf, body_offset) {
            Ok(body_length) => body_length,
            Err(error) => {
                self.drop_on_decryption_failure(error, decoded_pn);
                return None;
            }
        };

        // tracing::info!(
        //     "decrypted {} packet with PN {decoded_pn}",
        //     core::any::type_name::<H>()
        // );

        Some(Ok(PlainPacket {
            header: self.header,
            plain: self.payload.freeze(),
            payload_offset: self.payload_offset,
            undecoded_pn,
            decoded_pn,
            body_len: body_length,
        }))
    }

    pub fn decrypt_short_packet(
        mut self,
        hpk: &dyn HeaderProtectionKey,
        pk: &ArcOneRttPacketKeys,
        pn_decoder: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
    ) -> Option<Result<PlainPacket<H>, QuicError>> {
        let pkt_buf = self.payload.as_mut();
        let (undecoded_pn, key_phase) =
            match remove_protection_of_short_packet(hpk, pkt_buf, self.payload_offset) {
                Ok(Some((undecoded, key_phase))) => (undecoded, key_phase),
                Ok(None) => {
                    self.drop_on_remove_header_protection_failure();
                    return None;
                }
                Err(invalid_reverse_bits) => {
                    self.drop_on_reverse_bit_error(&invalid_reverse_bits);
                    return Some(Err(invalid_reverse_bits.into()));
                }
            };
        let decoded_pn = match pn_decoder(undecoded_pn) {
            Ok(pn) => pn,
            Err(invalid_pn) => {
                self.drop_on_invalid_pn(invalid_pn);
                return None;
            }
        };
        let pk = pk.lock_guard().get_remote(key_phase, decoded_pn);
        let body_offset = self.payload_offset + undecoded_pn.size();
        let body_length = match decrypt_packet(pk.as_ref(), decoded_pn, pkt_buf, body_offset) {
            Ok(body_length) => body_length,
            Err(error) => {
                self.drop_on_decryption_failure(error, decoded_pn);
                return None;
            }
        };

        // tracing::info!(
        //     "decrypted {} packet with PN {decoded_pn}",
        //     core::any::type_name::<H>()
        // );

        Some(Ok(PlainPacket {
            header: self.header,
            plain: self.payload.freeze(),
            payload_offset: self.payload_offset,
            undecoded_pn,
            decoded_pn,
            body_len: body_length,
        }))
    }
}

impl CipherPacket<InitialHeader> {
    pub fn drop_on_scid_unmatch(self) {
        qevent::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.payload.freeze(),
            details: Map {
                reason: "different scid with first initial packet"
            },
            trigger: PacketDroppedTrigger::Rejected
        })
    }
}

#[derive(Deref)]
pub struct PlainPacket<H> {
    #[deref]
    header: H,
    decoded_pn: u64,
    undecoded_pn: PacketNumber,
    plain: Bytes,
    payload_offset: usize,
    body_len: usize,
}

impl<H> PlainPacket<H> {
    pub fn size(&self) -> usize {
        self.plain.len()
    }

    pub fn pn(&self) -> u64 {
        self.decoded_pn
    }

    pub fn payload_len(&self) -> usize {
        self.undecoded_pn.size() + self.body_len
    }

    pub fn body(&self) -> Bytes {
        let packet_offset = self.payload_offset + self.undecoded_pn.size();
        self.plain
            .slice(packet_offset..packet_offset + self.body_len)
    }

    pub fn raw_info(&self) -> qevent::RawInfo {
        qevent::build!(qevent::RawInfo {
            length: self.plain.len() as u64,
            payload_length: self.payload_len() as u64,
            data: &self.plain,
        })
    }
}

impl<H> PlainPacket<H>
where
    PacketHeaderBuilder: for<'a> From<&'a H>,
{
    pub fn qlog_header(&self) -> PacketHeader {
        let mut builder = PacketHeaderBuilder::from(&self.header);
        qevent::build! {@field builder,
            packet_number: self.decoded_pn,
            length: self.payload_len() as u16
        };
        builder.build()
    }

    pub fn drop_on_conenction_closed(self) {
        qevent::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.raw_info(),
            details: Map {
                reason: "connection closed"
            },
            trigger: PacketDroppedTrigger::Genera
        })
    }

    pub fn log_received(&self, frames: impl Into<Vec<QuicFrame>>) {
        qevent::event!(PacketReceived {
            header: self.qlog_header(),
            frames,
            raw: self.raw_info(),
        })
    }
}
