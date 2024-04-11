// 这里实现流级别的控制

// 流是Sender、Recver的组合
pub enum Stream {
    // 有Client Initiated和Server Initiated之分
    // 在P2P的世界里，即是客户端，也是服务端，这里要改一下，
    // 对方创建的，被动流，和我方创建的主动流
    UniActive(SendingStream),
    UniPassive(RecvingStream),
    BiActive(SendingStream, RecvingStream),
    BiPassive(RecvingStream, SendingStream),
}

/**
 *        o
 *        | Create Stream (Sending)
 *        | Peer Creates Bidirectional Stream
 *        v
 *    +-------+
 *    | Ready | Send RESET_STREAM
 *    |       |-----------------------.
 *    +-------+                       |
 *        |                           |
 *        | Send STREAM /             |
 *        |      STREAM_DATA_BLOCKED  |
 *        v                           |
 *    +-------+                       |
 *    | Send  | Send RESET_STREAM     |
 *    |       |---------------------->|
 *    +-------+                       |
 *        |                           |
 *        | Send STREAM + FIN         |
 *        v                           v
 *    +-------+                   +-------+
 *    | Data  | Send RESET_STREAM | Reset |
 *    | Sent  |------------------>| Sent  |
 *    +-------+                   +-------+
 *        |                           |
 *        | Recv All ACKs             | Recv ACK
 *        v                           v
 *    +-------+                   +-------+
 *    | Data  |                   | Reset |
 *    | Recvd |                   | Recvd |
 *    +-------+                   +-------+
 * Figure 2: States for Sending Parts of Streams
 * 可以看到是个明显的状态机，那就按照状态机的模式去实现
 * SendingStream是管理发送数据区的，
 *   - 会被一直写入，直到结束（关闭）
 *   - 会被发送，并收到确认，让环形缓冲(Window)前进
 *   - 会重传
 *   - 会被中途取消
 */
pub(crate) enum SendingStream {
    // 主动创建，或者被动创建的双向流
    // 可以写入新数据，可以发送数据，可以取消掉
    Ready,
    // 可以写入新数据，可以发送数据，重传，确认数据，可以结束，也可以取消
    Send,
    // 不能写入新数据，相当于关闭后的发送流，
    // 可以继续发送待发送的，待确认的，确认未确认的，可以取消
    DataSent,
    // 已经取消的，不再写入、不再发送、也不再重传，只等reset被确认
    ResetSent,
    // 所有数据被确认，缓冲区没有数据待发送、待确认了，相当于结束
    DataRecved,
    // reset也被确认，
    ResetRecved,
}

/**
 *        o
 *        | Recv STREAM / STREAM_DATA_BLOCKED / RESET_STREAM
 *        | Create Bidirectional Stream (Sending)
 *        | Recv MAX_STREAM_DATA / STOP_SENDING (Bidirectional)
 *        | Create Higher-Numbered Stream
 *        v
 *    +-------+
 *    | Recv  | Recv RESET_STREAM
 *    |       |-----------------------.
 *    +-------+                       |
 *        |                           |
 *        | Recv STREAM + FIN         |
 *        v                           |
 *    +-------+                       |
 *    | Size  | Recv RESET_STREAM     |
 *    | Known |---------------------->|
 *    +-------+                       |
 *        |                           |
 *        | Recv All Data             |
 *        v                           v
 *    +-------+ Recv RESET_STREAM +-------+
 *    | Data  |--- (optional) --->| Reset |
 *    | Recvd |  Recv All Data    | Recvd |
 *    +-------+<-- (optional) ----+-------+
 *        |                           |
 *        | App Read All Data         | App Read Reset
 *        v                           v
 *    +-------+                   +-------+
 *    | Data  |                   | Reset |
 *    | Read  |                   | Read  |
 *    +-------+                   +-------+
 * Figure 3: States for Receiving Parts of Streams
 * 可以看到是个状态机，那就按状态机的方式来实现
 * RecvingStream是管理接收数据区的
 * 接收数据区要被一点点的填充，确认给对方，一点点地被读走
 *   - 会一直不停地接收
 *   - 会重组成连续的，并触发可读
 *   - 会被读取，然后驱动环形缓冲（Window）前进，并及时通告window大小
 *   - 会被取消，联动对应的发送端不要发送
 */
pub enum RecvingStream {
    // 初始状态，接收到新的流帧；或者创建双向流等
    // 可以接收数据，确认数据，并连续交付；也可以被reset
    Recv,
    // 确定了大小，从此不再有新数据
    SizeKnown,
    // 所有的数据都被接收完毕，可以接收数据，并连续交付
    DataRecved,
    // 被reset
    ResetRecved,
    // 所有数据都被读取完毕
    DataRead,
    // 应用感知到reset
    ResetRead,
}