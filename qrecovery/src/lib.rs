// pub mod data_space;
pub mod crypto;
pub mod index_deque;
pub mod rcvdpkt;
pub mod recv;
pub mod reliable;
pub mod rtt;
pub mod send;
pub mod space;
pub mod streams;

#[derive(Debug)]
pub enum QuicStream {
    ReadOnly(recv::Reader),
    WriteOnly(send::Writer),
    ReadWrite(recv::Reader, send::Writer),
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
