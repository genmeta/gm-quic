// ACK Frame {
//   Type (i) = 0x02..0x03,
//   Largest Acknowledged (i),
//   ACK Delay (i),
//   ACK Range Count (i),
//   First ACK Range (i),
//   ACK Range (..) ...,
//   [ECN Counts (..)],
// }

use std::ops::RangeInclusive;

use nom::{combinator::map, sequence::tuple};

use crate::varint::{be_varint, VarInt, WriteVarInt};

/// Receivers send ACK frames (types 0x02 and 0x03) to inform senders of packets they have
/// received and processed. The ACK frame contains one or more ACK Ranges.
///
/// See [ack-frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames) of QUIC RFC 9000.
///
/// The ACK Range Count is not included in the struct because it is an intermediate variable.
/// It can be obtained from the ranges when writing and is no longer needed after generating
/// the ranges when parsing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AckFrame {
    pub largest: VarInt,
    pub delay: VarInt,
    pub first_range: VarInt,
    pub ranges: Vec<(VarInt, VarInt)>,
    pub ecn: Option<EcnCounts>,
}

const ACK_FRAME_TYPE: u8 = 0x02;

const ECN_OPT: u8 = 0x1;

impl super::BeFrame for AckFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Ack(if self.ecn.is_some() { 1 } else { 0 })
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8 + 8 + self.ranges.len() * 16 + if self.ecn.is_some() { 24 } else { 0 }
    }

    fn encoding_size(&self) -> usize {
        1 + self.largest.encoding_size()
            + self.delay.encoding_size()
            + self.first_range.encoding_size()
            + self
                .ranges
                .iter()
                .map(|(gap, ack)| gap.encoding_size() + ack.encoding_size())
                .sum::<usize>()
            + if let Some(e) = self.ecn.as_ref() {
                e.encoding_size()
            } else {
                0
            }
    }
}

impl AckFrame {
    /// Set the value of the ECN (Explicit Congestion Notification) counter
    pub fn set_ecn(&mut self, ecn: EcnCounts) {
        self.ecn = Some(ecn);
    }

    /// Take the value of the ECN (Explicit Congestion Notification) counter
    pub fn take_ecn(&mut self) -> Option<EcnCounts> {
        self.ecn.take()
    }

    /// Iterate through the sequence numbers of the packets acknowledged by the iterative ACK frame,
    /// starting from the largest and going down.
    pub fn iter(&self) -> impl Iterator<Item = RangeInclusive<u64>> + '_ {
        let right = self.largest.into_inner();
        let left = right - self.first_range.into_inner();
        Some(left..=right).into_iter().chain(
            self.ranges
                .iter()
                .map(|(gap, range)| (gap.into_inner(), range.into_inner()))
                .scan(left, |largest, (gap, range)| {
                    let right = *largest - gap - 2;
                    let left = right - range;
                    *largest = left;
                    Some(left..=right)
                }),
        )
    }
}

/// The counts of Explicit Congestion Notification (ECN) types.
///
/// See [ecn-counts](https://www.rfc-editor.org/rfc/rfc9000.html#name-ecn-counts) of QUIC RFC 9000.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct EcnCounts {
    pub ect0: VarInt,
    pub ect1: VarInt,
    pub ce: VarInt,
}

impl EcnCounts {
    /// Calculates the encoding size of the [`EcnCounts`] struct.
    fn encoding_size(&self) -> usize {
        self.ect0.encoding_size() + self.ect1.encoding_size() + self.ce.encoding_size()
    }
}

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

impl<T: bytes::BufMut> super::io::WriteFrame<AckFrame> for T {
    fn put_frame(&mut self, frame: &AckFrame) {
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
            self.put_varint(&ecn.ect0);
            self.put_varint(&ecn.ect1);
            self.put_varint(&ecn.ce);
        }
    }
}

#[cfg(test)]
mod tests {
    use nom::combinator::flat_map;

    use super::{ack_frame_with_flag, be_ecn_counts, AckFrame, EcnCounts, ACK_FRAME_TYPE};
    use crate::{
        frame::io::WriteFrame,
        varint::{be_varint, VarInt},
    };

    #[test]
    fn test_read_ecn_count() {
        let input = vec![0x52, 0x34, 0x52, 0x34, 0x52, 0x34];
        let (input, ecn) = be_ecn_counts(&input).unwrap();
        assert!(input.is_empty());
        assert_eq!(
            ecn,
            EcnCounts {
                ect0: VarInt::from_u32(0x1234),
                ect1: VarInt::from_u32(0x1234),
                ce: VarInt::from_u32(0x1234),
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
        assert!(input.is_empty());
        assert_eq!(
            ack_frame,
            AckFrame {
                largest: VarInt::from_u32(0x1234),
                delay: VarInt::from_u32(0x1234),
                first_range: VarInt::from_u32(0x1234),
                ranges: vec![(VarInt::from_u32(3), VarInt::from_u32(20))],
                ecn: None,
            }
        );
    }

    #[test]
    fn test_write_ack_frame() {
        let mut buf = Vec::new();
        let frame = AckFrame {
            largest: VarInt::from_u32(0x1234),
            delay: VarInt::from_u32(0x1234),
            first_range: VarInt::from_u32(0x1234),
            ranges: vec![(VarInt::from_u32(3), VarInt::from_u32(20))],
            ecn: Some(EcnCounts {
                ect0: VarInt::from_u32(0x1234),
                ect1: VarInt::from_u32(0x1234),
                ce: VarInt::from_u32(0x1234),
            }),
        };

        buf.put_frame(&frame);
        assert_eq!(
            buf,
            vec![
                0x03, 0x52, 0x34, 0x52, 0x34, 0x01, 0x52, 0x34, 3, 20, // frame
                0x52, 0x34, 0x52, 0x34, 0x52, 0x34 // ecn
            ]
        );
    }

    #[test]
    fn test_ack_frame_into_iter() {
        // let mut frame = AckFrame::new(1000, 0, 0x1234, None).unwrap();
        let frame = AckFrame {
            largest: VarInt::from_u32(1000),
            delay: VarInt::from_u32(0x1234),
            first_range: VarInt::from_u32(0),
            ranges: vec![
                (VarInt::from_u32(0), VarInt::from_u32(2)),
                (VarInt::from_u32(4), VarInt::from_u32(30)),
                (VarInt::from_u32(7), VarInt::from_u32(40)),
            ],
            ecn: None,
        };
        // frame.alternating_gap_and_range(0, 2);
        // frame.alternating_gap_and_range(4, 30);
        // frame.alternating_gap_and_range(7, 40);

        let mut iter = frame.iter();
        assert_eq!(iter.next(), Some(1000..=1000));
        assert_eq!(iter.next(), Some(996..=998));
        assert_eq!(iter.next(), Some(960..=990));
        assert_eq!(iter.next(), Some(911..=951));
        assert_eq!(iter.next(), None);
    }
}
