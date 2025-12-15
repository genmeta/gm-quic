#![doc=include_str!("../../README.md")]

pub mod prelude {
    pub use ::qconnection;
    pub use qconnection::prelude::*;

    pub use crate::{
        client::{BindInterfaceError, ConnectServerError, QuicClient},
        server::{BuildListenersError, ListenersShutdown, QuicListeners, Server, ServerError},
    };

    pub mod handy {
        pub use qconnection::prelude::handy::*;

        pub use crate::cert::{ToCertificate, ToPrivateKey};
    }
}

pub mod builder {
    pub use qconnection::builder::*;

    pub use crate::{client::QuicClientBuilder, server::QuicListenersBuilder};
}

// Hidden modules used to integrate the code examples from the README into the cargo test
mod doc {
    #[doc=include_str!("../../README_CN.md")]
    mod zh {}

    // Omitted: Duplicate with crate documentation
    // #[doc=include_str!("../../README.md")]
    // mod en {}
}

pub use ::qconnection::{self, qbase, qevent, qinterface, qrecovery, qunreliable};

mod cert;
mod client;
mod server;
#[cfg(test)]
mod tests;
