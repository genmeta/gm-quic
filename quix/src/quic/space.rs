// 这里实现空间层的数据包读取

// 独立的可靠空间
struct Space {
    // 待发送的数据区引用
    // 已发送待确认信息记录
    // 重传队列

    // 已接收待重组的不连续信息记录
    // 待接收的最大数据包id
    // 接收缓冲区引用

    // 上次确认时间
    // 延迟Ack时间，
    // 供产生已接收数据的ack帧
}

impl Space {
    fn new() -> Self {
        todo!("新建一个空间，Init/Handshake/应用层空间")
    }

    fn write(&mut self, buf: &[u8]) -> Poll<Result<usize>> {
        todo!("向其中写内容")
    }

    fn recved(&mut self, packet: Vec<u8>) {
        todo!("收到了该空间的数据包，能够获取到该包id的")
    }

    fn recved_ack(&mut self, ack: &AckFrame) {
        todo!("收到发送数据的ack，要将已确认发送的标记；丢包的进行重传")
    }

    fn resend(&mut self, data: &Vec<u8>) {
        todo!("根据对方反馈的ack信息，将丢失的数据push进重传队列")
    }

    fn recved_data(&mut self, data: &Vec<u8>) {
        todo!("收到的数据，要放进接收缓冲区，等待读取")
    }

    fn try_ack(&mut self) -> Option<Frame<Ack>> {
        todo!("当需要发送ack数据时，应优先发送ack;如果没到发送ack的时间，则不必发送ack")
    }

    fn try_send(&mut self) -> Option<Frame<Data>> {
        todo!("需要发送数据包时，优先需要重传的，没有重传时再传待发送的")
    }
}
