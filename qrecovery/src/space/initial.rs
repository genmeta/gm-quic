use std::sync::{Arc, Mutex};

use qbase::frame::{self, CryptoFrame, InitialFrame};
use tokio::sync::mpsc::UnboundedSender;

use crate::crypto::{recv::CryptoIncoming, send::CryptoOutgoing};

use super::Transmit;

type InitalDataFrame = CryptoFrame;
pub struct InitailSpace(Arc<Mutex<super::Space<InitialFrame, InitalDataFrame, Transmission>>>);

#[derive(Debug)]
pub struct Transmission {
    input: CryptoIncoming,
    output: CryptoOutgoing,
}

impl Transmit<InitialFrame, InitalDataFrame> for Transmission {
    type Buffer = Vec<u8>;

    fn try_send(&mut self, buf: &mut Self::Buffer) -> Option<(InitalDataFrame, usize)> {
        todo!()
    }

    fn confirm_data(&mut self, data_frame: InitalDataFrame) {
        self.output.ack_rcvd(&data_frame.range());
    }

    fn may_loss(&mut self, data_frame: InitalDataFrame) {
        self.output.may_loss(&data_frame.range());
        todo!()
    }

    fn recv_frame(&mut self, frame: InitialFrame) {
        todo!()
    }

    fn recv_data(&mut self, data_frame: InitalDataFrame, data: bytes::Bytes) {
        self.input.recv(data_frame.offset.into(), data);
    }

    fn confirm(&mut self, _frame: InitialFrame) {}
}
