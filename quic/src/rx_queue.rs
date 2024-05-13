use qbase::packet::{
    ProtectedHandshakePacket, ProtectedInitialPacket, ProtectedOneRttPacket, ProtectedPacket,
    ProtectedZeroRttPacket,
};
use tokio::sync::mpsc;

use crate::ReceiveProtectedPacket;

#[derive(Debug)]
pub struct RxQueue<T> {
    tx: mpsc::Sender<T>,
    rx: Option<mpsc::Receiver<T>>,
}

impl<T: Send + 'static> RxQueue<T> {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(4);
        Self { tx, rx: Some(rx) }
    }

    fn push(&self, value: T) {
        // To prevent the receipt of data packets from blocking and affecting other
        // connections, we use tokio::spawn for asynchronous processing here.
        tokio::spawn({
            let tx = self.tx.clone();
            async move {
                if let Err(e) = tx.send(value).await {
                    // If an error occurs, it means that the receiver has been closed,
                    // and it is no longer necessary for the early spaces to receive data.
                    println!("rx queue send error: {}", e);
                }
            }
        });
    }

    // // Can only be called once, otherwise it will panic
    fn take_receiver(&mut self) -> mpsc::Receiver<T> {
        self.rx.take().unwrap()
    }
}

#[derive(Debug)]
pub struct RxQueues {
    initial: RxQueue<ProtectedInitialPacket>,
    handshake: RxQueue<ProtectedHandshakePacket>,
    zero_rtt: RxQueue<ProtectedZeroRttPacket>,
    one_rtt: RxQueue<ProtectedOneRttPacket>,
}

impl ReceiveProtectedPacket for RxQueues {
    fn receive_protected_packet(&mut self, protected_packet: ProtectedPacket) {
        match protected_packet {
            ProtectedPacket::Initial(packet) => self.initial.push(packet),
            ProtectedPacket::Handshake(packet) => self.handshake.push(packet),
            ProtectedPacket::ZeroRtt(packet) => self.zero_rtt.push(packet),
            ProtectedPacket::OneRtt(packet) => self.one_rtt.push(packet),
        }
    }
}

impl RxQueues {
    pub fn initial_receiver(&mut self) -> mpsc::Receiver<ProtectedInitialPacket> {
        self.initial.take_receiver()
    }

    pub fn handshake_receiver(&mut self) -> mpsc::Receiver<ProtectedHandshakePacket> {
        self.handshake.take_receiver()
    }

    pub fn zero_rtt_receiver(&mut self) -> mpsc::Receiver<ProtectedZeroRttPacket> {
        self.zero_rtt.take_receiver()
    }

    pub fn one_rtt_receiver(&mut self) -> mpsc::Receiver<ProtectedOneRttPacket> {
        self.one_rtt.take_receiver()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4)
    }
}
