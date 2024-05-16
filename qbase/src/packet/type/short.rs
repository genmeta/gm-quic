use crate::packet::SpinBit;
use bytes::BufMut;
use deref_derive::Deref;

const SHORT_HEADER_BIT: u8 = 0x00;

#[derive(Debug, Clone, Copy, Deref, PartialEq, Eq)]
pub struct OneRtt(#[deref] pub(crate) SpinBit);

impl From<u8> for OneRtt {
    fn from(value: u8) -> Self {
        OneRtt(SpinBit::from(value))
    }
}

impl From<OneRtt> for u8 {
    fn from(one_rtt: OneRtt) -> Self {
        SHORT_HEADER_BIT | super::FIXED_BIT | one_rtt.0.value()
    }
}

pub trait WriteShortType {
    fn put_short_type(&mut self, ty: &OneRtt);
}

impl<B: BufMut> WriteShortType for B {
    fn put_short_type(&mut self, ty: &OneRtt) {
        self.put_u8((*ty).into());
    }
}
