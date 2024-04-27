mod msg;
mod raw_io;
mod quic {
    mod cid;
    mod coding;
    mod connection;
    mod crypto;
    mod error;
    mod frames;
    mod packet;
    mod range_set;
    mod stream;
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
