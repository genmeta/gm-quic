pub mod connection;
pub mod crypto;
pub mod endpoint;
pub mod frame_queue;
pub mod path;

pub(crate) mod auto;

use frame_queue::ArcFrameQueue;
use qbase::packet::SpacePacket;

pub trait ReceiveProtectedPacket {
    fn receive_protected_packet(&mut self, protected_packet: SpacePacket);
}

// 收包队列，就用tokio::sync::mpsc::UnboundedChannel
// 收帧队列，得用VecDeque+is_closed+waker，外加Arc<Mutex>>包装，有close操作
// 之所以要封装VecDeque，为了一个包坏了，全部帧都得回退
// 收帧队列，又分为space的、connection的、path的3个

// 收包解帧任务，就用tokio::task::spawn产生，不同地从收包队列中取出包，取出密钥解帧，再放入对应的收帧队列中
// 包有Arc<Mutex<Path>>信息，收到的Path相关帧写入到
// Connection的收帧队列，只有一个，Arc<Mutex<Connection>>，收到的帧写入到这个队列中

// 发包的时候，由Path发起，但得先获得包id，若没东西发，包id就没必要获得，或者包id不允许退还，就发一个空包
// 先获取包序号，整理包头，计算剩余空间
// 写入path自己的帧。问题是，这个包丢了，path帧也得重传，怎么告知相应path，它的帧丢了呢？
//  有一张表，记录着那个包id是那个path发送的，当某个包丢的时候，告知path
// 写入Space的帧

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
