use std::convert::Infallible;

use qbase::{error::Error, frame::ConnectionCloseFrame};

use super::util::subscribe;

pub enum ConnEvent {
    ApplicationClose,
    TransportError(Error),
    ReceivedCcf(ConnectionCloseFrame),
}

#[derive(Debug, Clone)]
pub struct EventBroker {}

impl subscribe::Subscribe<ConnEvent> for EventBroker {
    type Error = Infallible;

    fn deliver(&self, _event: ConnEvent) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct EventHandler {}
