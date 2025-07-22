use std::time::Duration;

use crate::param::ParameterId;

pub fn client_parameters() -> super::ClientParameters {
    let mut params = super::ClientParameters::default();

    for (id, value) in [
        (ParameterId::InitialMaxStreamsBidi, 100u32),
        (ParameterId::InitialMaxStreamsUni, 100u32),
        (ParameterId::InitialMaxData, 1u32 << 20),
        (ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 20),
        (ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 20),
        (ParameterId::InitialMaxStreamDataUni, 1u32 << 20),
    ] {
        params.set(id, value).expect("unreachable");
    }

    params
        .set(ParameterId::MaxIdleTimeout, Duration::from_secs(5))
        .expect("unreachable");

    params
}

pub fn server_parameters() -> super::ServerParameters {
    let mut params = super::ServerParameters::default();

    for (id, value) in [
        (ParameterId::InitialMaxStreamsBidi, 100u32),
        (ParameterId::InitialMaxStreamsUni, 100u32),
        (ParameterId::InitialMaxData, 1u32 << 20),
        (ParameterId::InitialMaxStreamDataBidiLocal, 1u32 << 20),
        (ParameterId::InitialMaxStreamDataBidiRemote, 1u32 << 20),
        (ParameterId::InitialMaxStreamDataUni, 1u32 << 20),
    ] {
        params.set(id, value).expect("unreachable");
    }
    params
        .set(ParameterId::MaxIdleTimeout, Duration::from_secs(5))
        .expect("unreachable");

    params
}
