pub mod recv;
pub mod reliable;
pub mod send;
pub mod space;
pub mod streams;

#[derive(Debug)]
pub enum QuicStream {
    ReadOnly(recv::Reader),
    WriteOnly(send::Writer),
    ReadWrite(recv::Reader, send::Writer),
}
