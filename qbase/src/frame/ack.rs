// ACK Frame {
//   Type (i) = 0x02..0x03,
//   Largest Acknowledged (i),
//   ACK Delay (i),
//   ACK Range Count (i),
//   First ACK Range (i),
//   ACK Range (..) ...,
//   [ECN Counts (..)],
// }

use crate::varint::{err::Overflow, VarInt};
use std::{ops::RangeInclusive, vec::IntoIter};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AckRecord(pub u64);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AckFrame {
    pub largest: VarInt,
    pub delay: VarInt,
    pub first_range: VarInt,
    pub ranges: Vec<(VarInt, VarInt)>,
    pub ecn: Option<EcnCounts>,
}

pub(super) const ACK_FRAME_TYPE: u8 = 0x02;

const ECN_OPT: u8 = 0x1;

impl super::BeFrame for AckFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Ack(if self.ecn.is_some() { 1 } else { 0 })
    }
}

impl AckFrame {
    pub fn new(
        largest: u64,
        first_range: u32,
        delay: u64,
        ecn: Option<EcnCounts>,
    ) -> Result<Self, Overflow> {
        Ok(Self {
            largest: VarInt::try_from(largest)?,
            delay: VarInt::try_from(delay)?,
            first_range: VarInt::from_u32(first_range),
            ranges: Vec::new(),
            ecn,
        })
    }

    /// Safe: The number of gaps and ACK ranges to be acknowledged at a time cannot exceed 2^32.
    pub fn alternating_gap_and_range(&mut self, gap: u32, range: u32) {
        self.ranges
            .push((VarInt::from_u32(gap), VarInt::from_u32(range)));
    }

    pub fn take_ecn(&mut self) -> Option<EcnCounts> {
        self.ecn.take()
    }
}

impl std::convert::From<AckFrame> for AckRecord {
    fn from(frame: AckFrame) -> Self {
        AckRecord(frame.largest.into_inner())
    }
}

impl IntoIterator for AckFrame {
    type Item = RangeInclusive<u64>;
    type IntoIter = IntoAckIter;

    /// Note: Calling `into_iter` will consume the ownership of the `AckFrame`.
    /// Before doing so, it is important to handle the ECN information in the `AckFrame`.
    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            largest: self.largest.into_inner(),
            first_range: Some(self.first_range.into_inner()),
            iter: self.ranges.into_iter(),
        }
    }
}

#[derive(Debug)]
pub struct IntoAckIter {
    largest: u64,
    first_range: Option<u64>,
    iter: IntoIter<(VarInt, VarInt)>,
}

impl Iterator for IntoAckIter {
    type Item = RangeInclusive<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(first_range) = self.first_range.take() {
            let largest = self.largest;
            let smallest = largest - first_range;
            self.largest = smallest;
            Some(smallest..=largest)
        } else {
            self.iter.next().map(|(gap, range)| {
                let largest = self.largest - gap.into_inner() - 2;
                let smallest = largest - range.into_inner();
                self.largest = smallest;
                smallest..=largest
            })
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct EcnCounts {
    pub ect0: VarInt,
    pub ect1: VarInt,
    pub ce: VarInt,
}

pub(super) mod ext {
    use super::{AckFrame, EcnCounts, ECN_OPT};
    use crate::frame::ack::ACK_FRAME_TYPE;
    use crate::varint::ext::be_varint;
    use nom::combinator::map;
    use nom::sequence::tuple;

    pub fn ack_frame_with_flag(ecn_flag: u8) -> impl Fn(&[u8]) -> nom::IResult<&[u8], AckFrame> {
        move |input: &[u8]| {
            let (mut input, (largest, delay, count, first_range)) =
                tuple((be_varint, be_varint, be_varint, be_varint))(input)?;
            let mut ranges = Vec::new();
            let mut count = count.into_inner() as usize;
            while count > 0 {
                let (i, (gap, ack)) = tuple((be_varint, be_varint))(input)?;
                ranges.push((gap, ack));
                count -= 1;
                input = i;
            }

            let ecn = if ecn_flag & ECN_OPT != 0 {
                let (i, ecn) = be_ecn_counts(input)?;
                input = i;
                Some(ecn)
            } else {
                None
            };

            Ok((
                input,
                AckFrame {
                    largest,
                    delay,
                    first_range,
                    ranges,
                    ecn,
                },
            ))
        }
    }

    pub(super) fn be_ecn_counts(input: &[u8]) -> nom::IResult<&[u8], EcnCounts> {
        map(
            tuple((be_varint, be_varint, be_varint)),
            |(ect0, ect1, ce)| EcnCounts { ect0, ect1, ce },
        )(input)
    }

    pub trait WriteAckFrame {
        fn put_ecn_counts(&mut self, ecn: &EcnCounts);
        fn put_ack_frame(&mut self, frame: &AckFrame);
    }

    impl<T: bytes::BufMut> WriteAckFrame for T {
        fn put_ecn_counts(&mut self, ecn: &EcnCounts) {
            use crate::varint::ext::BufMutExt;
            self.put_varint(&ecn.ect0);
            self.put_varint(&ecn.ect1);
            self.put_varint(&ecn.ce);
        }

        fn put_ack_frame(&mut self, frame: &AckFrame) {
            use crate::varint::{ext::BufMutExt, VarInt};

            let mut frame_type = ACK_FRAME_TYPE;
            if frame.ecn.is_some() {
                frame_type |= ECN_OPT;
            }
            self.put_u8(frame_type);
            self.put_varint(&frame.largest);
            self.put_varint(&frame.delay);

            let ack_range_count = VarInt::try_from(frame.ranges.len()).unwrap();
            self.put_varint(&ack_range_count);
            self.put_varint(&frame.first_range);
            for (gap, ack) in &frame.ranges {
                self.put_varint(gap);
                self.put_varint(ack);
            }
            if let Some(ecn) = &frame.ecn {
                self.put_ecn_counts(ecn);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ext::{ack_frame_with_flag, be_ecn_counts, WriteAckFrame},
        AckFrame, EcnCounts, ACK_FRAME_TYPE,
    };
    use crate::varint::{ext::be_varint, VarInt};
    use nom::combinator::flat_map;

    #[test]
    fn test_read_ecn_count() {
        let input = vec![0x52, 0x34, 0x52, 0x34, 0x52, 0x34];
        let (input, ecn) = be_ecn_counts(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            ecn,
            EcnCounts {
                ect0: VarInt(0x1234),
                ect1: VarInt(0x1234),
                ce: VarInt(0x1234),
            }
        );
    }

    #[test]
    fn test_read_ack_frame() {
        let input = vec![0x02, 0x52, 0x34, 0x52, 0x34, 0x01, 0x52, 0x34, 3, 20];
        let (input, ack_frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() as u8 == ACK_FRAME_TYPE {
                ack_frame_with_flag(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type")
            }
        })(&input)
        .unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            ack_frame,
            AckFrame {
                largest: VarInt(0x1234),
                delay: VarInt(0x1234),
                first_range: VarInt(0x1234),
                ranges: vec![(VarInt(3), VarInt(20))],
                ecn: None,
            }
        );
    }

    #[test]
    fn test_write_ecn_count() {
        let mut buf = Vec::new();
        let ecn = EcnCounts {
            ect0: VarInt(0x1234),
            ect1: VarInt(0x1234),
            ce: VarInt(0x1234),
        };
        buf.put_ecn_counts(&ecn);
        assert_eq!(buf, vec![0x52, 0x34, 0x52, 0x34, 0x52, 0x34]);
    }

    #[test]
    fn test_write_ack_frame() {
        let mut buf = Vec::new();
        let mut frame = AckFrame::new(0x1234, 0x1234, 0x1234, None).unwrap();
        frame.alternating_gap_and_range(3, 20);

        buf.put_ack_frame(&frame);
        assert_eq!(
            buf,
            vec![0x02, 0x52, 0x34, 0x52, 0x34, 0x01, 0x52, 0x34, 3, 20]
        );
    }

    #[test]
    fn test_ack_frame_into_iter() {
        let mut frame = AckFrame::new(1000, 0, 0x1234, None).unwrap();
        frame.alternating_gap_and_range(0, 2);
        frame.alternating_gap_and_range(4, 30);
        frame.alternating_gap_and_range(7, 40);

        let mut iter = frame.into_iter();
        assert_eq!(iter.next(), Some(1000..=1000));
        assert_eq!(iter.next(), Some(996..=998));
        assert_eq!(iter.next(), Some(960..=990));
        assert_eq!(iter.next(), Some(911..=951));
        assert_eq!(iter.next(), None);
    }
}
