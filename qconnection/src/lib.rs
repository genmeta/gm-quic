pub mod connection;
pub mod crypto;
pub mod endpoint;
pub mod frame_queue;
pub mod path;

pub(crate) mod auto;

use frame_queue::ArcFrameQueue;
use path::ArcPath;
use qbase::packet::SpacePacket;

pub trait ReceiveProtectedPacket {
    fn receive_protected_packet(&mut self, protected_packet: SpacePacket);
}

// 发包的时候，由Path发起，但得先获得包id，若没东西发，包id就没必要获得，或者包id不允许退还，就发一个空包
// 先获取包序号，整理包头，计算剩余空间
// 写入path自己的帧。问题是，这个包丢了，path帧也得重传，怎么告知相应path，它的帧丢了呢？
//  有一张表，记录着那个包id是那个path发送的，当某个包丢的时候，告知path
// 写入Space的帧
pub fn transmit_initial_space(path: ArcPath) {
    // 0. 要发送，生成好一个Buffer，在栈上就可以
    //    不考虑Initial Keys还没准备好，因为作为Client，必先根据dcid生成Initial Keys；
    //    作为Server，必先根据收到包的scid生成Initial Keys，都会事先准备好Initial Keys

    // 1. 首先检查密钥有没有被淘汰，InitialSpace有没有被淘汰，若是淘汰了，就忽略。
    //    对Initial空间而言，可能Initial空间还没准备好，发送第一个包才确定Key。
    //    这就要求InitialSpace、ArcKey在销毁后，要返回一个None。
    //    或者，VecDeque<Box<dyn Transmit>>，弹出Initial空间的发送子，以做淘汰

    // 2. 若能发，先准备Initial包头，包头的内容除了length、pn之外是固定的，因此设计剩余空间评估函数
    //    与一并的缓冲区一起写入剩余缓冲区。这里有点麻烦的一点是，得先确认好，要写的所有数据长度，才能
    //    确认好length如何编码，才能从某个位置开始往buffer里面写入内容。
    //    (须知，Handshake与0RTT空间的帧种类更多，可能要写入Path的帧，再写入Space的帧)

    // 3. 写入内容之后，开始加密包内容，然后添加包头保护，然后发送出去
    todo!()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
