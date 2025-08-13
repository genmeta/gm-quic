use bytes::{BufMut, Bytes};

pub trait ContinuousData {
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool;

    fn to_bytes(&self) -> Bytes;
}

pub type DataPair<'a> = (&'a [u8], &'a [u8]);

impl ContinuousData for DataPair<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.0.len() + self.1.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.0.is_empty() && self.1.is_empty()
    }

    #[inline]
    fn to_bytes(&self) -> Bytes {
        Bytes::from([self.0, self.1].concat())
    }
}

impl ContinuousData for [u8] {
    #[inline]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self)
    }

    #[inline]
    fn to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

impl<const N: usize> ContinuousData for [u8; N] {
    #[inline]
    fn len(&self) -> usize {
        N
    }

    #[inline]
    fn is_empty(&self) -> bool {
        N == 0
    }

    #[inline]
    fn to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

impl ContinuousData for Vec<u8> {
    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    #[inline]
    fn to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

impl ContinuousData for Bytes {
    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    #[inline]
    fn to_bytes(&self) -> Bytes {
        self.clone()
    }
}

pub type NonData = ();

impl ContinuousData for NonData {
    #[inline]
    fn len(&self) -> usize {
        0
    }

    #[inline]
    fn is_empty(&self) -> bool {
        true
    }

    #[inline]
    fn to_bytes(&self) -> Bytes {
        Bytes::new()
    }
}

impl<D: ContinuousData + ?Sized> ContinuousData for &D {
    #[inline]
    fn len(&self) -> usize {
        D::len(*self)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        D::is_empty(*self)
    }

    #[inline]
    fn to_bytes(&self) -> Bytes {
        D::to_bytes(*self)
    }
}

pub trait WriteData<D: ContinuousData>: BufMut {
    fn put_data(&mut self, data: &D);
}

impl<T: BufMut> WriteData<DataPair<'_>> for T {
    #[inline]
    fn put_data(&mut self, data: &DataPair<'_>) {
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

impl<T: BufMut> WriteData<NonData> for T {
    #[inline]
    fn put_data(&mut self, &(): &()) {}
}
