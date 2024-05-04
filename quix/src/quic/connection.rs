use qrecovery::space::{InitailSpace, OneRttDataSpace};
use rustls::{ClientConfig, ServerConfig};

use super::{crypto::Crypto, packet::SpaceId};

enum Config {
    Client(ClientConfig),
    Server(ServerConfig),
}

pub(crate) struct Connection {
    crypto: Crypto,
    highest_space: SpaceId,
    initail_space: Option<InitailSpace>,
    data_space: Option<OneRttDataSpace>,
}

impl Connection {
    // todo
}
