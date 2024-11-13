use bytes::{BufMut, Bytes};

pub trait DescribeData {
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool;
}

impl DescribeData for (&[u8], &[u8]) {
    #[inline]
    fn len(&self) -> usize {
        self.0.len() + self.1.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.0.is_empty() && self.1.is_empty()
    }
}

impl DescribeData for &[u8] {
    #[inline]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self)
    }
}

impl<const N: usize> DescribeData for [u8; N] {
    #[inline]
    fn len(&self) -> usize {
        N
    }

    #[inline]
    fn is_empty(&self) -> bool {
        N == 0
    }
}

impl DescribeData for Bytes {
    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

pub trait WriteData<D: DescribeData>: BufMut {
    fn put_data(&mut self, data: &D);
}

impl<T: BufMut> WriteData<(&[u8], &[u8])> for T {
    #[inline]
    fn put_data(&mut self, data: &(&[u8], &[u8])) {
        self.put_slice(data.0);
        self.put_slice(data.1);
    }
}

impl<T: BufMut> WriteData<&[u8]> for T {
    #[inline]
    fn put_data(&mut self, data: &&[u8]) {
        self.put_slice(data)
    }
}

impl<const N: usize, T: BufMut> WriteData<[u8; N]> for T {
    #[inline]
    fn put_data(&mut self, data: &[u8; N]) {
        self.put_slice(data)
    }
}

impl<T: BufMut> WriteData<Bytes> for T {
    #[inline]
    fn put_data(&mut self, data: &Bytes) {
        self.put_slice(data);
    }
}
