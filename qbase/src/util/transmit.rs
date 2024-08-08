use bytes::BufMut;

#[derive(Debug, Clone, Copy)]
pub struct Constraints {
    // 信用额度，源于抗放大攻击；当验证通过后，将不再设限，表现为usize::MAX
    // 作用于所有数据，包括包头
    credit_limit: usize,
    // 发送配额，源于拥塞控制算法，随着时间的流逝，得到的本次Burst应当发送的数据量
    // 作用于ack-eliciting数据包，除非该包只发送Padding/Ack/Ccf帧
    send_quota: usize,
}

impl Constraints {
    pub fn new(credit_limit: usize, send_quota: usize) -> Self {
        Self {
            credit_limit,
            send_quota,
        }
    }

    pub fn constrain<'b>(&self, buf: &'b mut [u8]) -> &'b mut [u8] {
        let min_len = buf
            .remaining_mut()
            .min(self.credit_limit)
            .min(self.send_quota);
        &mut buf[..min_len]
    }

    pub fn commit(&mut self, len: usize, is_just_ack: bool) {
        self.credit_limit = self.credit_limit.saturating_sub(len);
        if !is_just_ack {
            self.send_quota = self.send_quota.saturating_sub(len);
        }
    }

    pub fn summary(&self, credit_limit: usize, send_quota: usize) -> (usize, usize) {
        (
            credit_limit.saturating_sub(self.credit_limit),
            send_quota.saturating_sub(self.send_quota),
        )
    }
}

pub trait ApplyConstraints {
    fn apply(self, constraints: &Constraints) -> Self;
}

impl ApplyConstraints for &mut [u8] {
    fn apply(self, constraints: &Constraints) -> Self {
        constraints.constrain(self)
    }
}
