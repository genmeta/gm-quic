use qbase::packet::ProtectedPacket;

pub mod connection;
pub mod crypto;
pub mod endpoint;
pub mod path;
pub mod rx_queue;

pub trait ReceiveProtectedPacket {
    fn receive_protected_packet(&mut self, protected_packet: ProtectedPacket);
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
