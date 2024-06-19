use std::collections::VecDeque;

pub mod flow;
use closing::ArcClosingState;
pub use flow::{ArcFlowController, FlowController};

use crate::path::ArcPath;

pub mod closing;

pub enum Controller {
    Normal {
        // 一个连接的所有路径，其中每个路径都包含一个与其自身相关的拥塞控制器以及抗放大攻击器
        pathes: VecDeque<ArcPath>,
        // 连接级的流量控制器
        flow: ArcFlowController,
    },
    // Closing状态，在3倍的PTO时间内，仅仅响应ConnectionCloseFrame
    Closing(ArcClosingState),
    // Draining状态，等待3倍的PTO时间，然后结束
    Draining,
    // 最终的结束状态，该连接可以释放
    End,
}
