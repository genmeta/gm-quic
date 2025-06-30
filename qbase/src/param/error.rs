use std::ops::RangeInclusive;

use thiserror::Error;

use crate::{
    param::{ParameterId, ParameterValueType},
    role::Role,
    varint::VarInt,
};

/// Error for QUIC parameters.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum Error {
    #[error("Parameter {0} is not defined")]
    UnknownParameterId(VarInt),
    #[error("{0} is not belong to {1}")]
    InvalidParameterId(ParameterId, Role),
    #[error("{0} is not supported for {1}")]
    InvalidValueType(ParameterId, ParameterValueType),
    #[error("{0}'s value {1} is out of bounds {2:?}")]
    OutOfBounds(ParameterId, u64, RangeInclusive<u64>),
}
