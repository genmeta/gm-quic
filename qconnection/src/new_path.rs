use std::{
    array, io,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::{ready, Future};
use qbase::{
    cid::{ArcCidCell, ConnectionId, Registry, MAX_CID_SIZE},
    packet::{
        header::{Encode},
        keys::AllKeys, LongHeaderBuilder, OneRttHeader, SpinBit,
    },
    util::TransportLimit,
};
use qcongestion::{
    congestion::{ArcCC, CongestionAlgorithm, MSS},
    CongestionControl,
};
use qrecovery::space::{Epoch, ReadSpace, Spaces};
use qudp::{ArcUsc, BATCH_SIZE};

use crate::{
    controller::{ArcFlowController},
    path::{ArcAntiAmplifier, Pathway},
    transmit,
};

enum PathState {
    Alive(RawPath),
    Dying(DyingPath),
    Dead,
}

#[derive(Clone)]
struct RawPath {
    usc: ArcUsc,
    cc: ArcCC,
    spaces: Spaces,
    keys: AllKeys,
    anti_amplifier: ArcAntiAmplifier<3>,
    flow_controller: ArcFlowController,
    pathway: Pathway,
    // todo: 整改 id_registry
    dcid: ArcCidCell,
}

impl RawPath {
    fn new(
        usc: ArcUsc,
        pathway: Pathway,
        spaces: Spaces,
        keys: AllKeys,
        flow_controller: ArcFlowController,
        dcid: ArcCidCell,
    ) -> Self {
        let cc = ArcCC::new(CongestionAlgorithm::Bbr, Duration::from_micros(100));
        let anti_amplifier = ArcAntiAmplifier::<3>::default();
        Self {
            usc,
            cc,
            anti_amplifier,
            spaces,
            keys,
            pathway,
            flow_controller,
            dcid,
        }
    }

    pub fn read(
        &self,
        scid: ConnectionId,
        dcid: ConnectionId,
        token: Vec<u8>,
        spin: SpinBit,
    ) -> ReadIntoPacket {
        ReadIntoPacket {
            cc: self.cc.clone(),
            anti_amplifier: self.anti_amplifier.clone(),
            flow_controler: self.flow_controller.clone(),
            spaces: self.spaces.clone(),
            keys: self.keys.clone(),
            dcid,
            scid,
            rest_token: token,
            spin,
        }
    }
}

struct ReadIntoPacket {
    cc: ArcCC,
    anti_amplifier: ArcAntiAmplifier<3>,
    flow_controler: ArcFlowController,
    spaces: Spaces,
    dcid: ConnectionId,
    scid: ConnectionId,
    rest_token: Vec<u8>,
    keys: AllKeys,
    spin: SpinBit,
}

impl ReadIntoPacket {
    fn read_initial_space(&self, buf: &mut [u8], limit: &mut TransportLimit) -> usize {
        let space = if let Some(space) = self.spaces[Epoch::Initial].as_ref() {
            space
        } else {
            return 0;
        };

        let inital_hdr =
            LongHeaderBuilder::with_cid(self.dcid, self.scid).initial(self.rest_token.clone());

        let max_header_size = inital_hdr.size() + 2; // 2 bytes reserved for packet length, max 16KB
        let (_, body_buf) = buf.split_at_mut(max_header_size);
        let ack_pkt = self.cc.need_ack(Epoch::Initial);

        let (pn, pn_size) = space.read_pn(body_buf, limit);
        let body_buf = &mut body_buf[pn_size..];
        let (len, is_ack_eliciting) = space.read_frame(limit, body_buf, ack_pkt);

        let body_len = pn_size + len;
        let fill_policy = transmit::FillPolicy::Redundancy;
        let (_, sent_bytes) = transmit::read_space_and_encrypt(
            buf,
            &inital_hdr,
            pn,
            pn_size,
            body_len,
            fill_policy,
            &self.keys.initial_keys.clone().unwrap(),
        );

        let ack = ack_pkt.map(|ack| ack.0);
        self.cc.on_pkt_sent(
            Epoch::Initial,
            pn,
            is_ack_eliciting,
            sent_bytes,
            is_ack_eliciting,
            ack,
        );
        sent_bytes
    }

    fn read_handshak_space(&self, buf: &mut [u8], limit: &mut TransportLimit) -> usize {
        let space = if let Some(space) = self.spaces[Epoch::Handshake].as_ref() {
            space
        } else {
            return 0;
        };

        let handshake_hdr = LongHeaderBuilder::with_cid(self.dcid, self.scid).handshake();
        let max_header_size = handshake_hdr.size() + 2; // 2 bytes reserved for packet length, max 16KB
        let (_, body_buf) = buf.split_at_mut(max_header_size);
        let ack_pkt = self.cc.need_ack(Epoch::Handshake);

        let (pn, pn_size) = space.read_pn(body_buf, limit);
        let body_buf = &mut body_buf[pn_size..];
        let (len, is_ack_eliciting) = space.read_frame(limit, body_buf, ack_pkt);

        let body_len = pn_size + len;
        let fill_policy = transmit::FillPolicy::Redundancy;
        let (_, sent_bytes) = transmit::read_space_and_encrypt(
            buf,
            &handshake_hdr,
            pn,
            pn_size,
            body_len,
            fill_policy,
            &self.keys.initial_keys.clone().unwrap(),
        );

        let ack = ack_pkt.map(|ack| ack.0);
        self.cc.on_pkt_sent(
            Epoch::Initial,
            pn,
            is_ack_eliciting,
            sent_bytes,
            is_ack_eliciting,
            ack,
        );
        sent_bytes
    }

    fn read_data_space(&self, buf: &mut [u8], limit: &mut TransportLimit) -> usize {
        let space = if let Some(space) = self.spaces[Epoch::Data].as_ref() {
            space
        } else {
            return 0;
        };

        let data_hdr = OneRttHeader {
            spin: self.spin,
            dcid: self.dcid,
        };

        let max_header_size = data_hdr.size() + 2; // 2 bytes reserved for packet length, max 16KB
        let (_, body_buf) = buf.split_at_mut(max_header_size);
        let ack_pkt = self.cc.need_ack(Epoch::Data);

        let (pn, pn_size) = space.read_pn(body_buf, limit);
        let body_buf = &mut body_buf[pn_size..];
        let (len, is_ack_eliciting) = space.read_frame(limit, body_buf, ack_pkt);

        let body_len = pn_size + len;
        let sent_bytes = transmit::read_1rtt_data_and_encrypt(
            buf,
            &data_hdr,
            self.keys.one_rtt_keys.clone().unwrap(),
            pn,
            pn_size,
            body_len,
        );

        let ack = ack_pkt.map(|ack| ack.0);
        self.cc.on_pkt_sent(
            Epoch::Initial,
            pn,
            is_ack_eliciting,
            sent_bytes,
            is_ack_eliciting,
            ack,
        );
        sent_bytes
    }
}

impl Future for ReadIntoPacket {
    type Output = io::Result<usize>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let cc_alow = ready!(self.cc.poll_send(cx));
        let anti_amplifier_alow = ready!(self.anti_amplifier.poll_get_credit(cx));
        let flow_controler_alow = ready!(self.flow_controler.sender.poll_apply(cx)).available();

        let mut limit = TransportLimit::new(anti_amplifier_alow, cc_alow, flow_controler_alow);

        // todo: 不必每次都申请新内存
        let mut buffers: [Vec<u8>; BATCH_SIZE] = array::from_fn(|_| vec![0u8; MSS]);
        let mut ioslices = Vec::new();
        for buffer in buffers.iter_mut() {
            if limit.available() == 0 {
                break;
            }

            for &epoch in Epoch::iter() {
                match epoch {
                    Epoch::Initial => todo!(),
                    Epoch::Handshake => todo!(),
                    Epoch::Data => todo!(),
                }
            }
            let buf = &mut buffer[0..];
            let sent_bytes = self.read_initial_space(buf, &mut limit);
            let buf = &mut buffer[0..sent_bytes];
            let sent_bytes = self.read_handshak_space(buf, &mut limit);
            let buf = &mut buffer[0..sent_bytes];
            let sent_bytes = self.read_data_space(buf, &mut limit);

            ioslices.push(io::IoSlice::new(&buffer[0..sent_bytes]));
            // read header and encrpyt body
        }
        todo!()
    }
}

struct DyingPath {}

#[derive(Clone)]
pub struct ArcPath(Arc<Mutex<PathState>>);

pub fn create_path(
    usc: ArcUsc,
    pathway: Pathway,
    spaces: Spaces,
    keys: AllKeys,
    flow_controller: ArcFlowController,
    cid_registry: Registry,
    spin: SpinBit,
) -> ArcPath {
    let dcid = cid_registry.remote.lock_guard().apply_cid();
    let raw_path = RawPath::new(usc, pathway, spaces, keys, flow_controller, dcid);
    // 发送任务
    let send_handle = tokio::spawn({
        let path = raw_path.clone();

        async move {
            let predicate = |_: &ConnectionId| true;
            let (scid, token) = match cid_registry.local.issue_cid(MAX_CID_SIZE, predicate).await {
                Ok(frame) => {
                    let token = (*frame.reset_token).to_vec();
                    let scid = frame.id;
                    // todo: put frame into space queue
                    (scid, token)
                }
                Err(_) => {
                    return;
                }
            };

            let dcid = path.dcid.clone().await;
            while path.read(scid, dcid, token.clone(), spin).await.is_ok() {}
        }
    });

    ArcPath(Arc::new(Mutex::new(PathState::Alive(raw_path))))
}
