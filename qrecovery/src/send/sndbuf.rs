use std::{
    borrow::BorrowMut,
    cmp::Ordering,
    collections::VecDeque,
    fmt::{Debug, Display},
    ops::Range,
};

/// To indicate the state of a data segment, it is colored.
#[derive(Default, PartialEq, Eq, Clone, Copy, Debug)]
enum Color {
    #[default]
    Pending,
    Flighting,
    Recved,
    Lost,
}

impl Color {
    fn prefix(&self) -> u64 {
        match self {
            Self::Pending => 0,
            Self::Flighting => 0b01 << 62,
            Self::Lost => 0b10 << 62,
            Self::Recved => 0b11 << 62,
        }
    }
}

#[derive(Eq, Clone, Copy)]
struct State(u64);

impl State {
    #[allow(dead_code)]
    const PREFIX: u64 = 0b11 << 62;
    const SUFFIX: u64 = u64::MAX >> 2;

    fn encode(pos: u64, color: Color) -> Self {
        Self(color.prefix() | pos)
    }

    fn offset(&self) -> u64 {
        self.0 & Self::SUFFIX
    }

    #[allow(dead_code)]
    fn set_offset(&mut self, value: u64) {
        debug_assert!(value <= Self::SUFFIX, "value({value}) overflow");
        self.0 = (self.0 & Self::PREFIX) | (value & Self::SUFFIX)
    }

    fn color(&self) -> Color {
        match self.0 >> 62 {
            0b00 => Color::Pending,
            0b01 => Color::Flighting,
            0b10 => Color::Lost,
            0b11 => Color::Recved,
            _ => unreachable!("impossible"),
        }
    }

    fn set_color(&mut self, value: Color) {
        self.0 = (self.0 & Self::SUFFIX) | value.prefix();
    }

    fn decode(&self) -> (u64, Color) {
        (self.offset(), self.color())
    }
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}: {:?}]", self.offset(), self.color())
    }
}

impl Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}: {:?}]", self.offset(), self.color())
    }
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.offset().eq(&other.offset())
    }
}

impl PartialOrd for State {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.offset().partial_cmp(&other.offset())
    }
}

pub struct PickIndicator<E> {
    estimate_capacity: E,
    flow_control_limit: Option<usize>,
}

impl<E> PickIndicator<E>
where
    E: Fn(u64) -> Option<usize>,
{
    pub fn new(estimate_capacity: E, flow_control_limit: Option<usize>) -> Self {
        Self {
            estimate_capacity,
            flow_control_limit,
        }
    }

    pub fn flow_control_limit(&self) -> usize {
        self.flow_control_limit.unwrap_or(0)
    }

    fn estimate_capacity(&self, offset: u64, color: Color) -> Option<usize> {
        let capacity = (self.estimate_capacity)(offset)?;
        match (color, self.flow_control_limit) {
            // 受到流量控制限制，并且不被限制
            (Color::Pending, Some(limit)) if limit != 0 => Some(limit.min(capacity)),
            // 不受流量控制限制，或者重传
            (Color::Pending, None) | (Color::Lost, _) => Some(capacity),
            _ => None,
        }
    }

    fn record(&mut self, taken: u64, color: Color) {
        if let (Color::Pending, Some(limit)) = (color, self.flow_control_limit.as_mut()) {
            *limit -= taken as usize;
        }
    }
}

/**
 * Self.0 意思是区间状态信息，它由一段VecDeque表示；
 * VecDeque中的每个元素是State，其中低62位是offset，代高2位是颜色，代表着到下一个State::offset的区间颜色。
 * Self.1代表着结尾位置，不包括Self.1; VecDeque中最后一个元素代表的状态区间，是最后一个State::offset到Self.1的区间。
 * 之所以采用这种数据结构，是考虑到CPU缓存行有64字节，可一次处理8段数据，足够很多小流传输了，很高效。
 * 即便是大流，其中相同状态的合并起来，各种不同状态的区间也不会很多，相比于链表、跳表、线段树等结构依然很高效。
 */
#[derive(Default, Debug)]
pub struct BufMap(VecDeque<State>, u64);

impl BufMap {
    // 追加写数据
    fn extend_to(&mut self, pos: u64) -> u64 {
        debug_assert!(
            pos < (1 << 62) && pos > self.1,
            "pos({pos}) overflow or less than {}",
            self.1
        );

        if pos > self.1 {
            let back = self.0.back();
            match back {
                Some(s) if s.color() == Color::Pending => {}
                _ => self.0.push_back(State::encode(self.1, Color::Pending)),
            };
            self.1 = pos;
        }
        self.1
    }

    // 挑选Lost/Pending的数据发送。越靠前的数据，越高优先级发送；
    // 丢包重传的数据，相比于Pending数据更靠前，因此具有更高的优先级。
    fn pick<E>(&mut self, picker: &mut PickIndicator<E>) -> Option<Range<u64>>
    where
        E: Fn(u64) -> Option<usize>,
    {
        // 先找到第一个能发送的区间，并将该区间染成Flight，返回原State
        self.0
            .iter_mut()
            .enumerate()
            .filter(|(.., state)| matches!(state.color(), Color::Pending | Color::Lost))
            .find_map(|(idx, state)| {
                let max = picker.estimate_capacity(state.offset(), state.color())?;
                Some((idx, max, state))
            })
            .map(|(index, max, state)| {
                let pre_state = *state; // 此处能归还self.0的可变借用
                state.set_color(Color::Flighting);
                (index, pre_state, max)
            })
            .map(|(index, pre_state, max)| {
                // 找到了一个合适的区间来发送，但检查区间长度是否足够，过长的话，还要拆区间一分为二
                let (start, color) = pre_state.decode();
                let mut end = self.0.get(index + 1).map(|s| s.offset()).unwrap_or(self.1);

                let mut i = self.same_before(index, Color::Flighting);
                if start + (max as u64) < end {
                    end = start + max as u64;
                    if i < index {
                        // 一分为二，如果本来有合并删除的区间，直接旧state回收复用
                        *self.0.get_mut(i + 1).unwrap() = State::encode(end, color);
                    } else {
                        self.0.insert(i + 1, State::encode(end, color));
                    }
                    i += 1;
                } else {
                    // TODO: 这里有个优化，如果紧跟着下一个是Lost或者Pending，可以连起来
                    self.merge_after(index, Color::Flighting);
                }
                // i仍然小于index，说明有需要删除直到index的state，意味着前向合并请求，一次drain即可
                if i < index {
                    self.0.drain(i + 1..=index);
                }
                picker.record(end - start, color);
                start..end
            })
    }

    // 收到了ack确认，确认的数据不需再发送，对于头部连续确认的数据，就可以删掉。
    // 寻找到ack区间所在的位置，将这些区间都染成Recved，然后检查前后是否有需要合并的区间，合并之。
    // ack区间，不能ack到Pending的数据，因为Pending的数据尚未发送过，当然无法被ack。
    fn ack_rcvd(&mut self, range: &Range<u64>) {
        let pos = self.0.binary_search_by(|s| s.offset().cmp(&range.start));
        let (mut drain_start, need_insert_at_start, mut drain_end, mut pre_color) = match pos {
            Ok(idx) => {
                let s = self.0.get_mut(idx).unwrap();
                let pre_color = s.color();
                debug_assert!(
                    pre_color != Color::Pending,
                    "Recved Range({:?}) covered Pending part from {}",
                    range,
                    s.offset()
                );
                s.set_color(Color::Recved);
                (
                    self.same_before(idx, Color::Recved) + 1,
                    false,
                    idx + 1,
                    pre_color,
                )
            }
            Err(idx) => {
                if idx == 0 {
                    (0, false, 0, Color::Recved)
                } else {
                    let s = self.0.get(idx - 1).unwrap();
                    let pre_color = s.color();
                    debug_assert!(
                        pre_color != Color::Pending,
                        "Recved Range({:?}) covered Pending part from {}",
                        range,
                        s.offset()
                    );
                    (idx, pre_color != Color::Recved, idx, pre_color)
                }
            }
        };

        let mut need_insert_at_end = false;
        loop {
            let entry = self.0.get(drain_end);
            match entry {
                Some(s) => match s.offset().cmp(&range.end) {
                    Ordering::Less => {
                        debug_assert!(
                            s.color() != Color::Pending,
                            "Recved Range({:?}) covered Pending parts from {}",
                            range,
                            s.offset()
                        );
                        drain_end += 1;
                        pre_color = s.color();
                    }
                    Ordering::Equal => {
                        // TODO: nightly版本, overflowing_sub 改为unchecked_sub更好
                        drain_end = self
                            .same_after(drain_end.overflowing_sub(1).0, Color::Recved)
                            .overflowing_add(1)
                            .0;
                        break;
                    }
                    Ordering::Greater => {
                        need_insert_at_end = pre_color != Color::Recved;
                        break;
                    }
                },
                None => {
                    debug_assert!(
                        range.end <= self.1,
                        "Recved Range({:?}) over {}",
                        range,
                        self.1
                    );
                    need_insert_at_end = range.end < self.1 && pre_color != Color::Recved;
                    break;
                }
            }
        }

        if need_insert_at_start {
            if drain_start < drain_end {
                *self.0.get_mut(drain_start).unwrap() = State::encode(range.start, Color::Recved);
            } else {
                self.0
                    .insert(drain_start, State::encode(range.start, Color::Recved));
            }
            drain_start += 1;
        }
        if need_insert_at_end {
            if drain_start < drain_end {
                *self.0.get_mut(drain_start).unwrap() = State::encode(range.end, pre_color);
            } else {
                self.0
                    .insert(drain_start, State::encode(range.end, pre_color));
            }
            drain_start += 1;
        }
        if drain_start < drain_end {
            self.0.drain(drain_start..drain_end);
        }
    }

    // 寻找第一个不是Recved的位置，意味着之前的数据都已经被确认接收，
    // 发送缓冲区可以移动到该位置，以让发送缓冲区腾出更多空间
    fn shift(&mut self) -> u64 {
        loop {
            let entry = self.0.front();
            match entry {
                Some(s) if s.color() == Color::Recved => {
                    self.0.pop_front();
                }
                Some(s) => {
                    return s.offset();
                }
                None => {
                    return self.1;
                }
            }
        }
    }

    // 判定某部分数据丢失，但不一定真的丢失，判定可能有误；丢失的数据需要优先重传。
    // 寻找到丢失区间覆盖的范围，其中若遇到Recved的区间，则忽略；只有Flighting/Lost的才可以丢失。
    // 然后检查Lost区间前后是否有需要合并的区间，合并之。
    // 同样地，Lost区间不能覆盖Pending的数据，因为Pending的数据尚未发送过，无法丢失。
    fn may_loss(&mut self, range: &Range<u64>) {
        let pos = self.0.binary_search_by(|s| s.offset().cmp(&range.start));
        let (mut drain_start, need_insert_at_start, mut drain_end, mut pre_color) = match pos {
            Ok(idx) => {
                let s = self.0.get_mut(idx).unwrap();
                let pre_color = s.color();
                debug_assert!(
                    pre_color != Color::Pending,
                    "Lost Range({:?}) covered Pending parts from {}",
                    range,
                    s.offset()
                );
                let mut drain_start = idx;
                if pre_color == Color::Flighting {
                    s.set_color(Color::Lost);
                    drain_start = self.same_before(idx, Color::Lost) + 1;
                } else {
                    drain_start += 1;
                }
                (drain_start, false, idx + 1, pre_color)
            }
            Err(idx) => {
                if idx == 0 {
                    (1, false, 0, Color::Recved)
                } else {
                    let s = self.0.get(idx - 1).unwrap();
                    let pre_color = s.color();
                    debug_assert!(
                        pre_color != Color::Pending,
                        "Lost Range({:?}) covered Pending parts from {}",
                        range,
                        s.offset()
                    );
                    if pre_color == Color::Recved {
                        // 另有安排，直接调用，lost_from(idx, range.end);
                        self.lost_from(idx, range.end);
                        return;
                    }
                    (idx, pre_color == Color::Flighting, idx, pre_color)
                }
            }
        };

        let mut need_insert_at_end = false;
        loop {
            let entry = self.0.get(drain_end);
            match entry {
                Some(s) => match s.offset().cmp(&range.end) {
                    Ordering::Less => {
                        debug_assert!(
                            s.color() != Color::Pending,
                            "Lost Range({:?}) covered Pending parts from {}",
                            range,
                            s.offset()
                        );
                        if s.color() == Color::Recved {
                            self.lost_from(drain_end + 1, range.end);
                            break;
                        } else {
                            drain_end += 1;
                            pre_color = s.color();
                        }
                    }
                    Ordering::Equal => {
                        drain_end = self
                            .same_after(drain_end.overflowing_sub(1).0, Color::Lost)
                            .overflowing_add(1)
                            .0;
                        break;
                    }
                    Ordering::Greater => {
                        need_insert_at_end = pre_color == Color::Flighting;
                        break;
                    }
                },
                None => {
                    debug_assert!(
                        range.end <= self.1,
                        "Lost Range({:?}) over {}",
                        range,
                        self.1
                    );
                    need_insert_at_end = range.end < self.1 && pre_color == Color::Flighting;
                    break;
                }
            };
        }

        if need_insert_at_start {
            if drain_start < drain_end {
                *self.0.get_mut(drain_start).unwrap() = State::encode(range.start, Color::Lost);
            } else {
                self.0
                    .insert(drain_start, State::encode(range.start, Color::Lost));
            }
            drain_start += 1;
        }
        if need_insert_at_end {
            if drain_start < drain_end {
                *self.0.get_mut(drain_start).unwrap() = State::encode(range.end, pre_color);
            } else {
                self.0
                    .insert(drain_start, State::encode(range.end, pre_color));
            }
            drain_start += 1;
        }
        if drain_start < drain_end {
            self.0.drain(drain_start..drain_end);
        }
    }
}

impl BufMap {
    fn same_before(&self, mut index: usize, color: Color) -> usize {
        loop {
            let pre = index.overflowing_sub(1).0;
            match self.0.get(pre) {
                Some(s) if s.color() == color => index = pre,
                _ => break,
            }
        }
        index
    }

    fn same_after(&self, mut index: usize, color: Color) -> usize {
        loop {
            let next = index.overflowing_add(1).0;
            match self.0.get(next) {
                Some(s) if s.color() == color => index = next,
                _ => break,
            }
        }
        index
    }

    fn merge_after(&mut self, index: usize, color: Color) {
        let same_after = self.same_after(index, color);
        if index < same_after {
            self.0.drain(index + 1..=same_after);
        }
    }

    // lost的辅助函数，将idx_start位置的变为Lost，然后向后继续判定丢失
    fn lost_from(&mut self, mut idx_start: usize, end: u64) {
        let mut idx = idx_start;
        let mut pre_color = Color::Recved;
        let mut need_insert_at_end = false;
        loop {
            let entry = self.0.get_mut(idx);
            match entry {
                Some(s) => match s.offset().cmp(&end) {
                    Ordering::Less => {
                        debug_assert!(
                            s.color() != Color::Pending,
                            "Lost Range.end({end}) covered Pending parts from {}",
                            s.offset()
                        );
                        pre_color = s.color();
                        if s.color() == Color::Recved {
                            // 另有安排，直接调用，lost_from(idx, range.end);
                            self.lost_from(idx + 1, end);
                            break;
                        } else {
                            s.set_color(Color::Lost);
                            idx += 1;
                        }
                    }
                    Ordering::Equal => {
                        idx = self
                            .same_after(idx.overflowing_sub(1).0, Color::Lost)
                            .overflowing_add(1)
                            .0;
                        break;
                    }
                    Ordering::Greater => {
                        need_insert_at_end = pre_color == Color::Flighting;
                        break;
                    }
                },
                None => {
                    debug_assert!(end <= self.1, "Lost Range.end({end}) over {}", self.1);
                    need_insert_at_end = end < self.1 && pre_color == Color::Flighting;
                    break;
                }
            }
        }
        if need_insert_at_end {
            if idx_start + 1 < idx {
                *self.0.get_mut(idx_start + 1).unwrap() = State::encode(end, pre_color);
            } else {
                self.0.insert(idx_start + 1, State::encode(end, pre_color));
            }
            idx_start += 1;
        }
        if idx_start + 1 < idx {
            self.0.drain(idx_start + 1..idx);
        }
    }
}

#[derive(Default, Debug)]
pub struct SendBuf {
    offset: u64,
    // 写入数据的环形队列，与接收队列不同的是，它是连续的
    data: VecDeque<u8>,
    state: BufMap,
}

impl SendBuf {
    pub fn with_capacity(n: usize) -> Self {
        Self {
            offset: 0,
            data: VecDeque::with_capacity(n),
            state: BufMap::default(),
        }
    }

    pub fn range(&self) -> Range<u64> {
        self.offset..self.state.1
    }

    // invoked by application layer
    pub fn write(&mut self, data: &[u8]) -> usize {
        // 写的数据量受流量控制限制，Crypto流则受Crypto流自身控制
        let n = data.len();
        if n > 0 {
            self.data.extend(data);
            self.state.extend_to(self.len() + n as u64);
        }

        n
    }

    pub fn is_empty(&self) -> bool {
        self.offset == 0 && self.data.is_empty()
    }

    // invoked by application layer
    // 发送缓冲区过去曾经累计写入到的数据总长度
    pub fn len(&self) -> u64 {
        self.state.1
    }

    pub fn remaining_mut(&self) -> usize {
        self.data.capacity() - self.data.len()
    }

    // 无需close：不在写入即可，具体到某个状态，才有close
    // 无需reset：状态转化间，需要reset，而Sender上下文直接释放即可
    // 无需clean：Sender上下文直接释放即可，
}

type Data<'s> = (u64, (&'s [u8], &'s [u8]));

impl SendBuf {
    // 挑选出可供发送的数据，限制长度不能超过len，以满足一个数据包能容的下一个完整的数据帧。
    // 返回的是一个切片，该切片的生命周期必须不长于SendBuf的生命周期，该切片可以被缓存至数据包
    // 被确认或者被判定丢失。
    pub fn pick_up<E>(&mut self, picker: &mut PickIndicator<E>) -> Option<Data>
    where
        E: Fn(u64) -> Option<usize>,
    {
        let picker = picker.borrow_mut();
        self.state.pick(picker).map(|range| {
            let start = (range.start - self.offset) as usize;
            let end = (range.end - self.offset) as usize;

            let (l, r) = self.data.as_slices();
            let s1 = &l[start.min(l.len())..l.len().min(end)];
            let s2 = &r[start.saturating_sub(l.len())..end.saturating_sub(l.len())];
            (range.start, (s1, s2))
        })
    }

    // 通过传输层接收到的对方的ack帧，确认某些包已经被接收到，这些包携带的数据即被确认。
    // ack只能确认Flighting/Lost状态的区间；如果确认的是Lost区间，意味着之前的判定丢包是错误的。
    pub fn on_data_acked(&mut self, range: &Range<u64>) {
        self.state.ack_rcvd(range);
        // 对于头部连续确认接收到的，还要前进，以免浪费空间
        let min_unrecved_pos = self.state.shift();
        if self.offset < min_unrecved_pos {
            self.data.drain(..(min_unrecved_pos - self.offset) as usize);
            self.offset = min_unrecved_pos;
        }
    }

    // 通过传输层收到的ack帧，判定有些数据包丢失，因为它之后的数据包都被确认了，
    // 或者距离发送该段数据之后相当长一段时间都没收到它的确认。
    pub fn may_loss_data(&mut self, range: &Range<u64>) {
        self.state.may_loss(range);
    }

    pub fn is_all_rcvd(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{BufMap, Color, State};
    use crate::send::sndbuf::PickIndicator;

    impl PickIndicator<()> {
        pub fn from_usize(size: usize) -> PickIndicator<impl Fn(u64) -> Option<usize>> {
            PickIndicator::new(move |_| Some(size), None)
        }
    }

    #[test]
    fn test_bufmap_empty() {
        let buf_map = BufMap::default();
        assert!(buf_map.0.is_empty());
    }

    #[test]
    fn test_bufmap_extend_to() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(100);
        assert_eq!(buf_map.0, vec![State::encode(0, Color::Pending)]);
        assert_eq!(buf_map.1, 100);

        buf_map.0.get_mut(0).unwrap().set_color(Color::Flighting);
        buf_map.extend_to(200);
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(100, Color::Pending)
            ]
        );
        assert_eq!(buf_map.1, 200);
    }

    #[test]
    fn test_bufmap_pick() {
        let mut buf_map = BufMap::default();
        let range = buf_map.pick(&mut PickIndicator::from_usize(20));
        assert_eq!(range, None);
        assert!(buf_map.0.is_empty());

        buf_map.extend_to(200);
        let range = buf_map.pick(&mut PickIndicator::from_usize(20));
        assert_eq!(range, Some(0..20));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(20, Color::Pending)
            ]
        );

        let range = buf_map.pick(&mut PickIndicator::from_usize(20));
        assert_eq!(range, Some(20..40));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(40, Color::Pending)
            ]
        );

        buf_map.0.insert(2, State::encode(50, Color::Lost));
        buf_map.0.insert(3, State::encode(120, Color::Pending));
        let range = buf_map.pick(&mut PickIndicator::from_usize(20));
        assert_eq!(range, Some(40..50));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(50, Color::Lost),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.0.get_mut(0).unwrap().set_color(Color::Recved);
        let range = buf_map.pick(&mut PickIndicator::from_usize(20));
        assert_eq!(range, Some(50..70));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(50, Color::Flighting),
                State::encode(70, Color::Lost),
                State::encode(120, Color::Pending)
            ]
        );

        let range = buf_map.pick(&mut PickIndicator::from_usize(130));
        assert_eq!(range, Some(70..120));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(50, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        let range = buf_map.pick(&mut PickIndicator::from_usize(130));
        assert_eq!(range, Some(120..200));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(50, Color::Flighting),
            ]
        );

        let range = buf_map.pick(&mut PickIndicator::from_usize(130));
        assert_eq!(range, None);
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(50, Color::Flighting),
            ]
        );
    }

    #[test]
    fn test_bufmap_recved() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(200);
        buf_map.pick(&mut PickIndicator::from_usize(120));
        buf_map.ack_rcvd(&(0..20));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(20, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.ack_rcvd(&(30..50));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(20, Color::Flighting),
                State::encode(30, Color::Recved),
                State::encode(50, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.ack_rcvd(&(25..55));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(20, Color::Flighting),
                State::encode(25, Color::Recved),
                State::encode(55, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.ack_rcvd(&(20..25));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(55, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.0.pop_front();
        buf_map.ack_rcvd(&(20..55));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(55, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.ack_rcvd(&(30..70));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(70, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.ack_rcvd(&(100..119));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(70, Color::Flighting),
                State::encode(100, Color::Recved),
                State::encode(119, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.pick(&mut PickIndicator::from_usize(200));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(70, Color::Flighting),
                State::encode(100, Color::Recved),
                State::encode(119, Color::Flighting),
            ]
        );

        buf_map.ack_rcvd(&(119..150));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(70, Color::Flighting),
                State::encode(100, Color::Recved),
                State::encode(150, Color::Flighting),
            ]
        );
        buf_map.ack_rcvd(&(150..200));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(70, Color::Flighting),
                State::encode(100, Color::Recved),
            ]
        );
    }

    #[test]
    #[should_panic]
    fn test_bufmap_invalid_recved() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(200);
        buf_map.pick(&mut PickIndicator::from_usize(120));
        buf_map.ack_rcvd(&(20..40));
        buf_map.0.insert(2, State::encode(30, Color::Pending));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(20, Color::Recved),
                // Alerting: 30..40 is Pending, never been sent, but they will be Recved
                State::encode(30, Color::Pending),
                State::encode(40, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );
        buf_map.ack_rcvd(&(0..50));
    }

    #[test]
    #[should_panic]
    fn test_bufmap_recved_overflow() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(200);
        buf_map.pick(&mut PickIndicator::from_usize(120));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );
        buf_map.ack_rcvd(&(110..121));
    }

    #[test]
    #[should_panic]
    fn test_bufmap_recved_over_end() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(200);
        buf_map.pick(&mut PickIndicator::from_usize(200));
        assert_eq!(buf_map.0, vec![State::encode(0, Color::Pending),]);
        buf_map.ack_rcvd(&(0..201));
    }

    #[test]
    fn test_bufmap_lost() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(200);
        buf_map.pick(&mut PickIndicator::from_usize(120));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(0..20));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Lost),
                State::encode(20, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(30..50));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Lost),
                State::encode(20, Color::Flighting),
                State::encode(30, Color::Lost),
                State::encode(50, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.ack_rcvd(&(0..10));
        buf_map.ack_rcvd(&(70..100));
        buf_map.0.pop_front();
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Flighting),
                State::encode(30, Color::Lost),
                State::encode(50, Color::Flighting),
                State::encode(70, Color::Recved),
                State::encode(100, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(15..25));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(25, Color::Flighting),
                State::encode(30, Color::Lost),
                State::encode(50, Color::Flighting),
                State::encode(70, Color::Recved),
                State::encode(100, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(10..20));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(25, Color::Flighting),
                State::encode(30, Color::Lost),
                State::encode(50, Color::Flighting),
                State::encode(70, Color::Recved),
                State::encode(100, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(60..110));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(25, Color::Flighting),
                State::encode(30, Color::Lost),
                State::encode(50, Color::Flighting),
                State::encode(60, Color::Lost),
                State::encode(70, Color::Recved),
                State::encode(100, Color::Lost),
                State::encode(110, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.ack_rcvd(&(20..55));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Recved),
                State::encode(55, Color::Flighting),
                State::encode(60, Color::Lost),
                State::encode(70, Color::Recved),
                State::encode(100, Color::Lost),
                State::encode(110, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(40..80));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Recved),
                State::encode(55, Color::Lost),
                State::encode(70, Color::Recved),
                State::encode(100, Color::Lost),
                State::encode(110, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.ack_rcvd(&(20..120));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Recved),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(50..80));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Recved),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(2..10));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Recved),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(30..50));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Recved),
                State::encode(120, Color::Pending),
            ]
        );
    }
}
