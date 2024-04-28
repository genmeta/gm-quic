pub mod config;
pub mod error;
pub mod frame;
pub mod streamid;
pub mod varint;

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
