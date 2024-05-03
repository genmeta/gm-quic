/// Application data space, 1-RTT data space
use crate::{
    recv::{self, Incoming, Reader},
    send::{self, Outgoing, Writer},
    AppStream,
};
use qbase::{
    frame::{OneRttFrame, *},
    streamid::*,
    varint::VarInt,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    task::{ready, Context, Poll, Waker},
};
use tokio::sync::mpsc::UnboundedSender;

type OneRttDataFrame = DataFrame;

pub struct OneRttDataSpace(Arc<Mutex<super::Space<OneRttFrame, OneRttDataFrame, Transmission>>>);

#[derive(Debug)]
pub struct Transmission {
    stream_ids: StreamIds,
    // 所有流的待写端，要发送数据，就得向这些流索取
    output: HashMap<StreamId, Outgoing>,
    // 所有流的待读端，收到了数据，交付给这些流
    input: HashMap<StreamId, Incoming>,
    // 对方主动创建的流
    accepted_streams: VecDeque<AppStream>,
    accpet_waker: Option<Waker>,

    frame_tx: UnboundedSender<OneRttFrame>,
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

    fn recv_data(&mut self, data_frame: OneRttDataFrame, body: bytes::Bytes) {
        match data_frame {
            OneRttDataFrame::Stream(stream) => {}
            OneRttDataFrame::Crypto(_crypto) => {
                // TODO: 处理加密数据
            }
        }
    }

    fn recv_frame(&mut self, frame: OneRttFrame) {
        match frame {
            OneRttFrame::Ping(_) => (),
            OneRttFrame::Stream(_frame) => {}
            _ => unreachable!("these are handled in connection layer"),
        }
    }
}

impl OneRttDataSpace {}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
