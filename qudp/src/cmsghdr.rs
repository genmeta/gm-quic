use std::{mem, ptr};

use libc::{c_int, c_uchar};

pub(super) struct CmsgHdr<'a, T: MsgHdr> {
    hdr: &'a mut T,
    cmsg: Option<&'a mut T::ControlMessage>,
    len: usize,
}

impl<'a, T: MsgHdr> CmsgHdr<'a, T> {
    pub(crate) unsafe fn new(hdr: &'a mut T) -> Self {
        Self {
            cmsg: hdr.first_cmsg().as_mut(),
            hdr,
            len: 0,
        }
    }

    pub(crate) fn append<V: Copy>(&mut self, level: c_int, ty: c_int, value: V) {
        assert!(mem::align_of::<V>() <= mem::align_of::<T::ControlMessage>());
        let space = T::ControlMessage::space(mem::size_of_val(&value));
        assert!(
            self.hdr.capacity() >= self.len + space,
            "no enough space for cmsg"
        );
        let cmsg = self.cmsg.take().expect("no cmsg available");
        cmsg.set(
            level,
            ty,
            T::ControlMessage::cmsg_len(mem::size_of_val(&value)),
        );
        unsafe {
            ptr::write(cmsg.data() as *const V as *mut V, value);
        }
        self.len += space;
        self.cmsg = unsafe { self.hdr.next(cmsg).as_mut() };
    }

    pub(crate) fn finish(&mut self) {
        self.hdr.set_len(self.len);
    }
}
pub(crate) trait MsgHdr {
    type ControlMessage: Cmsg;

    fn first_cmsg(&self) -> *mut Self::ControlMessage;

    fn next(&self, cmsg: &Self::ControlMessage) -> *mut Self::ControlMessage;

    fn set_len(&mut self, len: usize);

    fn capacity(&self) -> usize;
}

pub(crate) trait Cmsg {
    fn cmsg_len(length: usize) -> usize;

    fn space(length: usize) -> usize;

    fn data(&self) -> *mut c_uchar;

    fn set(&mut self, level: c_int, ty: c_int, len: usize);
}

pub(crate) struct Iter<'a, T: MsgHdr> {
    hdr: &'a T,
    cmsg: Option<&'a T::ControlMessage>,
}

impl<'a, T: MsgHdr> Iter<'a, T> {
    /// # Safety
    ///
    /// `hdr.msg_control` must point to memory outliving `'a` which can be soundly read for the
    /// lifetime of the constructed `Iter` and contains a buffer of cmsgs, i.e. is aligned for
    /// `cmsghdr`, is fully initialized, and has correct internal links.
    pub(crate) unsafe fn new(hdr: &'a T) -> Self {
        Self {
            hdr,
            cmsg: hdr.first_cmsg().as_ref(),
        }
    }
}

impl<'a, T: MsgHdr> Iterator for Iter<'a, T> {
    type Item = &'a T::ControlMessage;
    fn next(&mut self) -> Option<Self::Item> {
        let current = self.cmsg.take()?;
        self.cmsg = unsafe { self.hdr.next(current).as_ref() };
        Some(current)
    }
}

/// # Safety
///
/// `cmsg` must refer to a cmsg containing a payload of type `T`
pub(crate) unsafe fn decode<T: Copy, C: Cmsg>(cmsg: &C) -> T {
    assert!(mem::align_of::<T>() <= mem::align_of::<C>());
    ptr::read(cmsg.data() as *const T)
}
