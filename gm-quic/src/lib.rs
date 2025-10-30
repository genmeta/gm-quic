pub mod prelude {
    pub use ::qconnection;
    pub use qconnection::prelude::*;

    pub use crate::{
        client::QuicClient,
        server::{QuicListeners, Server, ServerError},
    };

    pub mod handy {
        pub use qconnection::prelude::handy::*;

        pub use crate::cert::{ToCertificate, ToPrivateKey};
    }
}

pub mod builder {
    pub use qconnection::builder::*;

    pub use crate::{
        client::{BindInterfaceError, QuicClientBuilder},
        server::{BuildServerError, QuicListenersBuilder},
    };
}

pub use ::qconnection::{self, qbase, qevent, qinterface, qrecovery, qunreliable};

mod cert;
mod client;
mod server;
#[cfg(test)]
mod tests;
