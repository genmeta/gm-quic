use nom::IResult;

use super::{BeFrame, FrameType};
use crate::{
    util::{DescribeData, WriteData},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// DATAGRAM Frame
///
/// ```text
/// DATAGRAM Frame {
///   Type (i) = 0x30..0x31,
///   [Length (i)],
///   Datagram Data (..),
/// }
/// ```
///
/// See [datagram frame types](https://www.rfc-editor.org/rfc/rfc9000.html#name-datagram-frame-types)
/// of [An Unreliable Datagram Extension to QUIC](https://www.rfc-editor.org/rfc/rfc9221.html)
/// for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramFrame {
    pub length: Option<VarInt>,
}

impl DatagramFrame {
    /// Create a new `DatagramFrame` with the given length.
    pub fn new(length: Option<VarInt>) -> Self {
        Self { length }
    }
}

impl BeFrame for DatagramFrame {
    fn frame_type(&self) -> FrameType {
        FrameType::Datagram(self.length.is_some() as _)
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.length.map(VarInt::encoding_size).unwrap_or_default()
    }
}

/// Return a parser for DATAGRAM frames with a flag,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn datagram_frame_with_flag(flag: u8) -> impl FnOnce(&[u8]) -> IResult<&[u8], DatagramFrame> {
    move |input| {
        let (remain, len) = if flag == 1 {
            be_varint(input).map(|(remain, len)| (remain, Some(len)))?
        } else {
            (input, None)
        };
        Ok((remain, DatagramFrame { length: len }))
    }
}

impl<T, D> super::io::WriteDataFrame<DatagramFrame, D> for T
where
    T: bytes::BufMut + WriteData<D>,
    D: DescribeData,
{
    fn put_data_frame(&mut self, frame: &DatagramFrame, data: &D) {
        self.put_u8(frame.frame_type().into());
        if let Some(len) = frame.length {
            self.put_varint(&len);
        }
        self.put_data(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::io::WriteDataFrame;

    #[test]
    fn test_datagram_frame() {
        let frame = DatagramFrame {
            length: Some(VarInt::from_u32(3)),
        };
        assert_eq!(frame.frame_type(), FrameType::Datagram(1));
        assert_eq!(frame.max_encoding_size(), 1 + 8);
        assert_eq!(frame.encoding_size(), 1 + 1);
    }

    #[test]
    fn test_datagram_frame_with_flag() {
        let input = [0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        let expected_output = DatagramFrame {
            length: Some(VarInt::from_u32(5)),
        };
        let (remain, frame) = datagram_frame_with_flag(1)(&input).unwrap();
        assert_eq!(remain, &[0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(frame, expected_output);
    }

    #[test]
    fn test_datagram_frame_with_flag_no_length() {
        let input = b"114514";
        let expected_output = DatagramFrame { length: None };
        let (remain, frame) = datagram_frame_with_flag(0)(input).unwrap();
        assert_eq!(remain, input);
        assert_eq!(frame, expected_output);
    }

    #[test]
    fn test_put_datagram_frame_with_length() {
        let frame = DatagramFrame {
            length: Some(VarInt::from_u32(3)),
        };
        let mut buf = Vec::new();
        buf.put_data_frame(&frame, &[0x01, 0x02, 0x03]);
        assert_eq!(&buf, &[0x31, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_put_datagram_frame_no_length() {
        let frame = DatagramFrame { length: None };
        let mut buf = Vec::new();
        buf.put_data_frame(&frame, &[0x01, 0x02, 0x03]);
        assert_eq!(&buf, &[0x30, 0x01, 0x02, 0x03]);
    }
}
