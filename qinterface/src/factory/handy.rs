use crate::{
    factory::ProductInterface,
    logical::{BindUri, handy},
};

#[cfg(all(feature = "qudp", any(unix, windows)))]
pub static DEFAULT_QUIC_IO_FACTORY: fn(BindUri) -> handy::qudp::UdpSocketController =
    |bind_uri| handy::qudp::UdpSocketController::bind(bind_uri);

#[cfg(not(all(feature = "qudp", any(unix, windows))))]
pub static DEFAULT_QUIC_IO_FACTORY: fn(BindUri) -> handy::unsupported::Unsupported =
    |bind_uri| handy::unsupported::bind(bind_uri);

const _: () = {
    const fn assert_product_interface_factory<F: ProductInterface + Copy>(_: &F) {}
    assert_product_interface_factory(&DEFAULT_QUIC_IO_FACTORY);
};
