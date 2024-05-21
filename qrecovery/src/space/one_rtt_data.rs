/// Application data space, 1-RTT data space
use crate::{crypto::CryptoStream, streams::Streams};

pub type OneRttDataSpace = super::Space<CryptoStream, Streams>;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
