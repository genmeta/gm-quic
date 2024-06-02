use congestion::Epoch;
use qbase::frame::AckFrame;
use std::{
    task::{Context, Poll},
    time::Instant,
};

pub mod bbr;
pub mod congestion;
pub mod rtt;
pub use rtt::RawRtt;
pub mod delivery_rate;
pub mod min_max;
pub mod pacing;

pub trait CongestionControl {
    /// 轮询是否可以发包，若可以，返回可以发包的数据量；该数据量包含各个空间的包能发的数据量总和
    /// 如果返回0，代表着结束，不再发包，并停止循环
    fn poll_send(&self, cx: &mut Context<'_>) -> Poll<usize>;

    /// 发某个空间的包时，询问是否需要发送AckFrame，若需要，返回该Path接收的最大包id及其接收时间
    /// 不需要的话，则返回None。每次需要发包，每个Epoch都需要询问
    fn need_ack(&self, space: Epoch) -> Option<(u64, Instant)>;

    /* 下面发送PathChallenge和PathResponse帧，像是Path的，单独抽象在另外一个trait比较合适
    /// 发数据空间的包时，询问是否需要发送PathChallengeFrame，可在0RTT和1RTT数据包内发送
    fn need_path_challenge(&self) -> Option<PathChallengeFrame>;

    /// 发数据空间的包时，询问是否需要发送PathResponseFrame，只能在1RTT数据包内发送
    fn need_path_response(&self) -> Option<PathResponseFrame>;
    */

    /// 每当发送一个数据包后，由Path的cc记录发包信息，供未来确认时计算RTT和发送速率，并减少发送信用
    /// 最后一个参数，是这次发包是否携带了ack frame，若没携带，是None；若携带了，则是ack frame的最大包号
    /// 若有Ack信息，也要记录下来。未来该包被确认，那么该AckFrame中largest之前的，接收到的包，通知ack观察者失活
    fn on_pkt_sent(
        &self,
        space: Epoch,
        pn: u64,
        is_ack_elicition: bool,
        sent_bytes: usize,
        in_flight: bool,
        ack: Option<u64>,
    );

    /// 当收到AckFrame，其中有该Path的部分包被确认，调用该函数，驱动拥塞控制算法演进
    /// 如果该包中有ack frame，那么ack.largest之前的收包记录未来就不需要在AckFrame中再同步了，需通知ack观察者
    fn on_ack(&self, space: Epoch, ack_frame: &AckFrame);

    /// 处理AckFrame中的largest及ack_delay字段，供Path的cc采样rtt，不可重复采样
    /// 调用该函数后，也意味着AckFrame都被确认完了，可以判断Path过往发过的包，哪些丢了，并反馈
    /// #[deprecated("duplicate with on_ack")]
    /// fn on_rtt_sample(&mut self, space: Epoch, largest_pn: u64, ack_delay: Duration);

    /// 每当收到一个数据包，记录下，根据这些记录，决定下次发包时，是否需要带上AckFrame，作用于poll_send的返回值中
    /// 另外，这个记录不是持续增长的，得向前滑动，靠on_acked(pn)及该pn中有AckFrame记录驱动滑动
    fn on_recv_pkt(&self, space: Epoch, pn: u64, is_ack_elicition: bool);
}

pub trait ObserveLoss {
    /// 当收到AckFrame，largest_acked_pn都被确认了，那往前数3个没被ack的包，可判定为丢失
    /// 前3个数据包，如果超时时间过长，超过了PTO，也应判定为丢包，调用该函数，通知丢包观察者
    ///（丢包观察者可能是可靠空间的发送端，用于ARQ丢包重传机制，也可能是一个channel的sender）
    fn may_loss_pkt(&self, space: Epoch, pn: u64);
}

/// 如果一个类型实现了SlideWindow，其inactivate用于标记淘汰窗口左边的元素。
/// 那Drop时，就会自动检查左边连续被淘汰的元素，将其滑过去。
pub trait SlideWindow {
    fn inactivate(&self, idx: u64);
}

pub trait ObserveAck {
    type Guard: SlideWindow;
    /// 收包记录作为滑动窗口也要向前滑动；当一个Path的收包记录产生的AckFrame被对方收到时，那这个Path过往收到的包
    /// 都不必记录了，可以淘汰。
    /// 需知，一个Path收到的包不需要被记录，不代表其他Path的包也不需被记录。只有等各个path过去接收的包都不需要被记录，
    /// 那么Space级别的包号连续的不被记录的，才可以向前滑动
    /// #[deprecated]
    /// fn on_ack_be_acked(&self, space: Epoch, pn: u64);

    /// 其实用函数作用命名，可以如下命名，感觉更好一些
    /// 当发送的AckFrame被确认，那该AckFrame中的largest之前的，该path接收的包号，
    /// 都可以淘汰/失活了，不需再出现在后续的AckFrame中，即调用此函数通知外部观察者
    /// fn inactivate_rcvd_record(&self, space: Epoch, pn: u64);

    fn guard(&self, space: Epoch) -> Self::Guard;
}
