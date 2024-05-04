/// Application data space, 1-RTT data space

use crate::{
    crypto::{recv::CryptoIncoming, send::CryptoOutgoing},
    recv::{self, Incoming, Reader},
    send::{self, Outgoing, Writer},
    AppStream,
};
use qbase::{
    error::Error,
    frame::{DataFrame, OneRttFrame},
};
use std::{
    sync::{Arc, Mutex},
    task::{ready, Context, Poll, Waker},
};
use tokio::sync::mpsc::UnboundedSender;

type OneRttDataFrame = DataFrame;

pub struct OneRttDataSpace(Arc<Mutex<super::Space<OneRttFrame, OneRttDataFrame, Transmission>>>);

#[derive(Debug)]
pub struct Transmission {
    accpet_waker: Option<Waker>,

    frame_tx: UnboundedSender<OneRttFrame>,

    // TODO: 创建加密流
    crypto_output: CryptoOutgoing,
    crypto_input: CryptoIncoming,
}

impl super::Transmit<OneRttFrame, OneRttDataFrame> for Transmission {
    type Buffer = Vec<u8>;

    fn try_send(&mut self, _buf: &mut Self::Buffer) -> Option<(OneRttDataFrame, usize)> {
        todo!()
    }

    fn confirm_data(&mut self, data_frame: OneRttDataFrame) {
        match data_frame {
            OneRttDataFrame::Stream(_stream) => {}
            OneRttDataFrame::Crypto(_crypto) => {
                // TODO: 处理加密数据流
            }
        }
    }

    fn may_loss(&mut self, data_frame: OneRttDataFrame) {
        match data_frame {
            OneRttDataFrame::Stream(_stream) => {}
            OneRttDataFrame::Crypto(_crypto) => {
                // 处理加密数据流的丢包
            }
        }
    }

    fn recv_data(&mut self, data_frame: OneRttDataFrame, body: bytes::Bytes) -> Result<(), Error> {
        match data_frame {
            OneRttDataFrame::Stream(stream) => {}
            OneRttDataFrame::Crypto(_crypto) => {
                // TODO: 处理加密数据
            }
        }
        Ok(())
    }

    fn recv_frame(&mut self, frame: OneRttFrame) -> Result<(), Error> {
        match frame {
            OneRttFrame::Ping(_) => (),
            OneRttFrame::Stream(_frame) => {}
            _ => unreachable!("these are handled in connection layer"),
        }
        Ok(())
    }

    fn confirm(&mut self, _frame: OneRttFrame) {}
}

impl OneRttDataSpace {}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
