// pub mod data_space;
pub mod crypto;
pub mod rcvdpkt;
pub mod recv;
pub mod reliable;
pub mod send;
pub mod space;
pub mod streams;
pub mod unreliable;

#[derive(Debug)]
pub enum QuicStream {
    ReadOnly(recv::Reader),
    WriteOnly(send::Writer),
    ReadWrite(recv::Reader, send::Writer),
}
