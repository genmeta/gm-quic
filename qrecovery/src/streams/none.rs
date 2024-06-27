use super::DataStreams;

/// 在Initial和Handshake空间中，是不需要传输Streams的，此时可以使用NoDataStreams
#[derive(Debug, Clone)]
pub struct NoDataStreams;

impl AsRef<DataStreams> for NoDataStreams {
    fn as_ref(&self) -> &DataStreams {
        unreachable!()
    }
}
