use super::varint::VarInt;
use getset::{CopyGetters, Getters, MutGetters, Setters};
use std::time::Duration;

/// The maximum number of CIDs we bother to issue per connection
const LOC_CID_COUNT: u64 = 8;
const RESET_TOKEN_SIZE: usize = 16;
const MAX_CID_SIZE: usize = 20;
const MIN_INITIAL_SIZE: u16 = 1200;
/// <https://www.rfc-editor.org/rfc/rfc9000.html#name-datagram-size>
const INITIAL_MTU: u16 = 1200;
const MAX_UDP_PAYLOAD: u16 = 65527;
const TIMER_GRANULARITY: Duration = Duration::from_millis(1);
/// Maximum number of streams that can be uniquely identified by a stream ID
const MAX_STREAM_COUNT: u64 = 1 << 60;

// QUIC的config配置
#[derive(Getters, Setters, MutGetters, CopyGetters, Debug)]
pub struct TransportConfig {
    #[getset(get_copy = "pub", set = "pub")]
    max_concurrent_bidi_streams: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    max_concurrent_uni_streams: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    max_idle_timeout: Option<VarInt>,
    #[getset(get_copy = "pub", set = "pub")]
    stream_recv_window: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    recv_window: VarInt,
    #[getset(get_copy = "pub", set = "pub")]
    send_window: u64,

    #[getset(get_copy = "pub", set = "pub")]
    max_tlps: u32,
    #[getset(get_copy = "pub", set = "pub")]
    packet_threshold: u32,
    #[getset(get_copy = "pub", set = "pub")]
    time_threshold: f32,
    #[getset(get_copy = "pub", set = "pub")]
    initial_rtt: Duration,
    #[getset(get_copy = "pub", set = "pub")]
    initial_mtu: u16,
    #[getset(get_copy = "pub", set = "pub")]
    min_mtu: u16,
    //  mtu_discovery_config: Option<MtuDiscoveryConfig>,
    #[getset(get_copy = "pub", set = "pub")]
    persistent_congestion_threshold: u32,
    #[getset(get_copy = "pub", set = "pub")]
    keep_alive_interval: Option<Duration>,
    #[getset(get_copy = "pub", set = "pub")]
    crypto_buffer_size: usize,
    #[getset(get_copy = "pub", set = "pub")]
    allow_spin: bool,
    #[getset(get_copy = "pub", set = "pub")]
    datagram_recv_buffer_size: Option<usize>,
    #[getset(get_copy = "pub", set = "pub")]
    datagram_send_buffer_size: usize,
    // pub(crate) congestion_controller_factory: Box<dyn congestion::ControllerFactory + Send + Sync>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        const EXPECTED_RTT: u32 = 100; // ms
        const MAX_STREAM_BANDWIDTH: u32 = 12500 * 1000; // bytes/s
                                                        // Window size needed to avoid pipeline
                                                        // stalls
        const STREAM_RWND: u32 = MAX_STREAM_BANDWIDTH / 1000 * EXPECTED_RTT;

        Self {
            max_concurrent_bidi_streams: 100u32.into(),
            max_concurrent_uni_streams: 100u32.into(),
            max_idle_timeout: Some(VarInt(10_000)),
            stream_recv_window: STREAM_RWND.into(),
            recv_window: VarInt::MAX,
            send_window: (8 * STREAM_RWND).into(),

            max_tlps: 2,
            packet_threshold: 3,
            time_threshold: 9.0 / 8.0,
            initial_rtt: Duration::from_millis(333), // per spec, intentionally distinct from EXPECTED_RTT
            initial_mtu: INITIAL_MTU,
            min_mtu: INITIAL_MTU,
            // mtu_discovery_config: None,
            persistent_congestion_threshold: 3,
            keep_alive_interval: None,
            crypto_buffer_size: 16 * 1024,
            allow_spin: true,
            datagram_recv_buffer_size: Some(STREAM_RWND as usize),
            datagram_send_buffer_size: 1024 * 1024,
            // congestion_controller_factory: Box::new(Arc::new(congestion::CubicConfig::default())),
        }
    }
}

mod tests {
    use super::TransportConfig;
    use super::VarInt;

    #[test]
    fn it_works() {
        let mut config = TransportConfig::default();
        config.set_max_concurrent_bidi_streams(VarInt::from_u32(20));
        assert_eq!(config.max_concurrent_bidi_streams, VarInt::from_u32(20));
        dbg!(config);
    }
}
