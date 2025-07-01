use std::io;

#[cfg(all(feature = "qudp", any(unix, windows)))]
use qbase::net::addr::BindAddr;

use crate::{factory::ProductQuicIO, iface::handy::*};

#[cfg(all(feature = "qudp", any(unix, windows)))]
pub static DEFAULT_QUIC_IO_FACTORY: fn(BindAddr) -> io::Result<qudp::UdpSocketController> =
    qudp::UdpSocketController::bind;

#[cfg(not(all(feature = "qudp", any(unix, windows))))]
pub static DEFAULT_QUIC_IO_FACTORY: fn(BindAddr) -> io::Result<unsuppoeted::Unsuppoeted> =
    unsuppoeted::Unsuppoeted::bind;

fn _assert_impl_quic_io_factory() {
    fn assert_impl<F: ProductQuicIO + Copy>(_: F) {}
    assert_impl(DEFAULT_QUIC_IO_FACTORY);
}
