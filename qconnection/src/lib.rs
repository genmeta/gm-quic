pub mod connection;
pub mod crypto;
pub mod endpoint;
pub mod frame_queue;
pub mod path;

pub(crate) mod auto;
pub mod transmit;

use frame_queue::ArcFrameQueue;
use qbase::packet::SpacePacket;

pub trait ReceiveProtectedPacket {
    fn receive_protected_packet(&mut self, protected_packet: SpacePacket);
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
