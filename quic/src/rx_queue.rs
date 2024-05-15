use crate::ReceiveProtectedPacket;
use qbase::packet::{HandshakePacket, InitialPacket, OneRttPacket, SpacePacket, ZeroRttPacket};
use qrecovery::{rtt::Rtt, space};
use tokio::sync::mpsc;

#[derive(Debug)]
pub struct RxQueue<P> {
    tx: mpsc::Sender<P>,
    rx: Option<mpsc::Receiver<P>>,
}

impl<P: Send + 'static> RxQueue<P> {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(4);
        Self { tx, rx: Some(rx) }
    }

    pub fn push(&self, value: P) {
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
}

impl<P> RxQueue<P>
where
    P: Send + 'static,
{
    // Can only be called once, otherwise it will panic
    fn take_receiver(&mut self) -> mpsc::Receiver<P> {
        self.rx.take().unwrap()
    }

    pub async fn pipe(&mut self, space: impl space::ReceivePacket<Packet = P>, rtt: &mut Rtt) {
        let mut rx = self.take_receiver();
        loop {
            match rx.recv().await {
                Some(packet) => {
                    let _ = space.receive_packet(packet, rtt);
                }
                None => {
                    break;
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct RxQueues {
    initial: RxQueue<InitialPacket>,
    handshake: RxQueue<HandshakePacket>,
    zero_rtt: RxQueue<ZeroRttPacket>,
    one_rtt: RxQueue<OneRttPacket>,
}

impl ReceiveProtectedPacket for RxQueues {
    fn receive_protected_packet(&mut self, protected_packet: SpacePacket) {
        match protected_packet {
            SpacePacket::Initial(packet) => self.initial.push(packet),
            SpacePacket::Handshake(packet) => self.handshake.push(packet),
            SpacePacket::ZeroRtt(packet) => self.zero_rtt.push(packet),
            SpacePacket::OneRtt(packet) => self.one_rtt.push(packet),
        }
    }
}

impl RxQueues {
    pub fn initial_receiver(&mut self) -> mpsc::Receiver<InitialPacket> {
        self.initial.take_receiver()
    }

    pub fn handshake_receiver(&mut self) -> mpsc::Receiver<HandshakePacket> {
        self.handshake.take_receiver()
    }

    pub fn zero_rtt_receiver(&mut self) -> mpsc::Receiver<ZeroRttPacket> {
        self.zero_rtt.take_receiver()
    }

    pub fn one_rtt_receiver(&mut self) -> mpsc::Receiver<OneRttPacket> {
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
