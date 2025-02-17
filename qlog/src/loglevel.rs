use serde::{Deserialize, Serialize};

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Error {
    pub code: Option<u64>,
    pub message: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Warning {
    pub code: Option<u64>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Info {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Debug {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verbose {
    pub message: String,
}
