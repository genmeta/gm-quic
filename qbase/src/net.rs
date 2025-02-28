mod addr;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Waker,
};

pub use addr::*;
use futures::task::AtomicWaker;

/// 为何不用AtomicWaker，主要是AtomicWaker没有清理，只能通过wake唤醒来清理，不够灵活
pub struct SendWaker {
    // conn-level wakers
    // 新CryptoStream、Frames的写入(不包括新的StreamFrame写入)
    // 以及重传，包括CryptoStream、StreamFrame、Frames
    unlimited_write_waker: AtomicWaker,
    unlimited_write_times: Arc<AtomicU64>, // 重传调用次数记录
    // 有新数据写入，唤醒发送
    write_waker: AtomicWaker,
    write_bytes: Arc<AtomicU64>, // 写入数据次数记录
    // flow control waker
    flow_waker: AtomicWaker,
    flow_limit: Arc<AtomicU64>, // 流量控制限制

    dcid_waker: AtomicWaker,
    dcid_applied: Arc<AtomicBool>,
    amplify_waker: AtomicWaker,
    amplify_more: Arc<AtomicBool>,
    validate_waker: AtomicWaker,
    validated: Arc<AtomicBool>,
    /// 需要3个空间的
    ack_waker: AtomicWaker,
    ack_again: Arc<AtomicBool>,
    burst_waker: AtomicWaker,
    burst_again: Arc<AtomicBool>,
}

impl SendWaker {
    pub fn new(
        unlimited_write_times: Arc<AtomicU64>,
        write_bytes: Arc<AtomicU64>,
        flow_limit: Arc<AtomicU64>,
        dcid_applied: Arc<AtomicBool>,
        amplify_more: Arc<AtomicBool>,
        validate: Arc<AtomicBool>,
        ack_again: Arc<AtomicBool>,
        burst_again: Arc<AtomicBool>,
    ) -> Self {
        Self {
            unlimited_write_waker: AtomicWaker::new(),
            unlimited_write_times,
            write_waker: AtomicWaker::new(),
            write_bytes,
            flow_waker: AtomicWaker::new(),
            flow_limit,
            dcid_waker: AtomicWaker::new(),
            dcid_applied,
            amplify_waker: AtomicWaker::new(),
            amplify_more,
            validate_waker: AtomicWaker::new(),
            validated: validate,
            ack_waker: AtomicWaker::new(),
            ack_again,
            burst_waker: AtomicWaker::new(),
            burst_again,
        }
    }

    fn try_set_burst_waker(&mut self, waker: &Waker) -> bool {
        self.burst_waker.register(waker);
        self.burst_again.load(Ordering::Acquire) == false
    }

    /// Retrun true if the waker is set, the task suspended and waiting for the waker to wake up.
    /// Return false indicates that the task would be woken up immediately.
    fn try_set_retran_waker(&mut self, waker: &Waker, old_retraned_times: u64) -> bool {
        self.unlimited_write_waker.register(waker);
        self.unlimited_write_times.load(Ordering::Acquire) <= old_retraned_times
    }

    /// Retrun true if the waker is set, the task suspended and waiting for the waker to wake up.
    /// Return false indicates that the task would be woken up immediately.
    fn try_set_written_waker(&mut self, waker: &Waker, old_written: u64) -> bool {
        self.write_waker.register(waker);
        self.write_bytes.load(Ordering::Acquire) <= old_written
    }

    fn try_set_ack_waker(&mut self, waker: &Waker) -> bool {
        self.ack_waker.register(waker);
        self.ack_again.load(Ordering::Acquire) == false
    }

    /// Retrun true if the waker is set, the task suspended and waiting for the waker to wake up.
    /// Return false indicates that the task would be woken up immediately.
    fn try_set_flow_waker(&mut self, waker: &Waker, old_flow_limit: u64) -> bool {
        self.flow_waker.register(waker);
        self.flow_limit.load(Ordering::Acquire) <= old_flow_limit
    }

    fn try_set_dcid_waker(&mut self, waker: &Waker) -> bool {
        self.dcid_waker.register(waker);
        self.dcid_applied.load(Ordering::Acquire) == false
    }

    fn try_set_amplify_waker(&mut self, waker: &Waker) -> bool {
        self.amplify_waker.register(waker);
        self.amplify_more.load(Ordering::Acquire) == false
    }

    fn try_set_validate_waker(&mut self, waker: &Waker) -> bool {
        self.validate_waker.register(waker);
        self.validated.load(Ordering::Acquire) == false
    }
}

impl SendWaker {
    pub fn wait_to_write_data_from(
        &mut self,
        waker: &Waker,
        old_written: u64,
        old_retraned_times: u64,
    ) {
        if !self.try_set_ack_waker(waker) {
            waker.wake_by_ref();
            self.ack_waker.take();
            return;
        }
        if !self.try_set_retran_waker(waker, old_retraned_times) {
            waker.wake_by_ref();
            self.unlimited_write_waker.take();
            self.ack_waker.take();
            return;
        }
        if !self.try_set_written_waker(waker, old_written) {
            waker.wake_by_ref();
            self.write_waker.take();
            self.unlimited_write_waker.take();
            self.ack_waker.take();
        }
    }

    pub fn wait_to_flow_expand_from(
        &mut self,
        waker: &Waker,
        old_flow_limit: u64,
        old_retraned_times: u64,
    ) {
        if !self.try_set_ack_waker(waker) {
            waker.wake_by_ref();
            self.ack_waker.take();
            return;
        }
        if !self.try_set_retran_waker(waker, old_retraned_times) {
            waker.wake_by_ref();
            self.unlimited_write_waker.take();
            self.ack_waker.take();
            return;
        }
        if !self.try_set_flow_waker(waker, old_flow_limit) {
            waker.wake_by_ref();
            self.flow_waker.take();
            self.unlimited_write_waker.take();
            self.ack_waker.take();
        }
    }

    pub fn wait_to_burst(&mut self, waker: &Waker) {
        if !self.try_set_burst_waker(waker) {
            waker.wake_by_ref();
            self.burst_waker.take();
        }
        if !self.try_set_ack_waker(waker) {
            waker.wake_by_ref();
            self.ack_waker.take();
            self.burst_waker.take();
        }
    }

    pub fn wait_to_apply_dcid(&mut self, waker: &Waker) {
        if !self.try_set_dcid_waker(waker) {
            waker.wake_by_ref();
            self.dcid_waker.take();
        }
    }

    pub fn wait_to_amplify(&mut self, waker: &Waker) {
        if !self.try_set_amplify_waker(waker) {
            waker.wake_by_ref();
            self.amplify_waker.take();
        }
        if !self.try_set_validate_waker(waker) {
            waker.wake_by_ref();
            self.validate_waker.take();
            self.amplify_waker.take();
        }
    }
}

impl SendWaker {
    pub fn wake_by_need_ack(&mut self) {
        if let Some(waker) = self.ack_waker.take() {
            waker.wake();
            self.unlimited_write_waker.take();
            self.write_waker.take();
            self.flow_waker.take();
            self.burst_waker.take();
        }
    }

    pub fn wake_by_writting(&mut self) {
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
            self.unlimited_write_waker.take();
            self.ack_waker.take();
        }
    }

    pub fn wake_by_retran(&mut self) {
        if let Some(waker) = self.unlimited_write_waker.take() {
            waker.wake();
            self.write_waker.take();
            self.ack_waker.take();
            self.flow_waker.take();
        }
    }

    pub fn wake_by_flow_expand(&mut self) {
        if let Some(waker) = self.flow_waker.take() {
            waker.wake();
            self.unlimited_write_waker.take();
            self.ack_waker.take();
        }
    }

    pub fn wake_by_burst(&mut self) {
        if let Some(waker) = self.burst_waker.take() {
            waker.wake();
            self.ack_waker.take();
        }
    }

    pub fn wake_by_apply_dcid(&mut self) {
        if let Some(waker) = self.dcid_waker.take() {
            waker.wake();
        }
    }

    pub fn wake_by_more_allowance(&mut self) {
        if let Some(waker) = self.amplify_waker.take() {
            waker.wake();
            self.validate_waker.take();
        }
    }

    pub fn wake_by_validation_passed(&mut self) {
        if let Some(waker) = self.validate_waker.take() {
            waker.wake();
            self.amplify_waker.take();
        }
    }
}
