use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct Error {
    pub code: Option<u64>,
    pub message: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct Warning {
    pub code: Option<u64>,
    pub message: Option<String>,
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Info {
    pub message: String,
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Debug {
    pub message: String,
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Verbose {
    pub message: String,
}

crate::gen_builder_method! {
    ErrorBuilder   => Error;
    WarningBuilder => Warning;
    InfoBuilder    => Info;
    DebugBuilder   => Debug;
    VerboseBuilder => Verbose;
}
