// quic connection级别的收发包处理

pub(crate) struct Connection {
    // quic协议路由子实例，可能是全局的

    // 各连接ID，每个连接ID都能接收、发送数据包

    // 各连接ID的轮询接收子任务handle

    // 当前连接ID

    // 拥塞控制器，根据速度、定时器等驱动发送，记录已发送数据待确认、确认数据

    // 不同层所代表的空间，可靠传输在这一层实现；包含空间要发送的数据、要确认的数据、已确认的数据

    // streams集合，已发现的streams

    // 新Stream Accept异步算子
}