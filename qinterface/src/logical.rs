mod alive;
mod bind_uri;
mod collection;
mod rw_iface;

// handy（qudp）是可选的
pub mod handy;

pub use alive::InterfaceFailure;
pub use bind_uri::{
    BindUri, BindUriSchema, ParseBindUriError, ParseBindUriSchemeError, TryIntoSocketAddrError,
};
pub use collection::QuicInterfaces;
pub use rw_iface::{BindInterface, QuicInterface};
