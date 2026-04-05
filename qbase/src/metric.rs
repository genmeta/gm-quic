use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Metrics for tracking data volumes in a QUIC connection.
///
/// This struct provides atomic counters to track:
/// - Data written by application but not yet sent
/// - Data sent but not yet acknowledged
/// - Data sent and acknowledged
#[derive(Debug, Default)]
pub struct ConnectionMetrics {
    /// Data written by application layer but not yet sent by transport layer
    pending_bytes: AtomicU64,
    /// Data sent by transport layer but not yet acknowledged by peer
    inflight_bytes: AtomicU64,
    /// Data sent and acknowledged by peer
    acked_bytes: AtomicU64,
}

impl ConnectionMetrics {
    /// Increments the pending send bytes counter when application writes data.
    ///
    /// Called when application layer writes data to a stream.
    pub fn new_pending(&self, bytes: u64) {
        self.pending_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Updates counters when transport layer sends new data.
    ///
    /// Increments sent_unacked_bytes and decrements pending_send_bytes.
    /// Called when transport layer sends new stream data.
    pub fn on_data_sent(&self, bytes: u64) {
        self.inflight_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.pending_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Updates counters when data is acknowledged by peer.
    ///
    /// Increments sent_acked_bytes and decrements sent_unacked_bytes.
    /// Called when receiving acknowledgment for stream data.
    pub fn on_data_acked(&self, bytes: u64) {
        self.acked_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.inflight_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Gets the current amount of data pending to be sent.
    pub fn pending_bytes(&self) -> u64 {
        self.pending_bytes.load(Ordering::Relaxed)
    }

    /// Gets the current amount of data sent but not acknowledged.
    pub fn inflight_bytes(&self) -> u64 {
        self.inflight_bytes.load(Ordering::Relaxed)
    }

    /// Gets the total amount of data sent and acknowledged.
    pub fn acked_bytes(&self) -> u64 {
        self.acked_bytes.load(Ordering::Relaxed)
    }
}

/// Arc-wrapped ConnectionMetrics for shared ownership across the connection.
pub type ArcConnectionMetrics = Arc<ConnectionMetrics>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_metrics_new() {
        let metrics = ConnectionMetrics::default();
        assert_eq!(metrics.pending_bytes(), 0);
        assert_eq!(metrics.inflight_bytes(), 0);
        assert_eq!(metrics.acked_bytes(), 0);
    }

    #[test]
    fn test_add_pending_send() {
        let metrics = ConnectionMetrics::default();
        metrics.new_pending(100);
        assert_eq!(metrics.pending_bytes(), 100);
        metrics.new_pending(50);
        assert_eq!(metrics.pending_bytes(), 150);
    }

    #[test]
    fn test_on_data_sent() {
        let metrics = ConnectionMetrics::default();
        metrics.new_pending(200);
        metrics.on_data_sent(150);
        assert_eq!(metrics.pending_bytes(), 50);
        assert_eq!(metrics.inflight_bytes(), 150);
    }

    #[test]
    fn test_on_data_acked() {
        let metrics = ConnectionMetrics::default();
        metrics.new_pending(200);
        metrics.on_data_sent(150);
        metrics.on_data_acked(100);
        assert_eq!(metrics.pending_bytes(), 50);
        assert_eq!(metrics.inflight_bytes(), 50);
        assert_eq!(metrics.acked_bytes(), 100);
    }

    #[test]
    fn test_full_data_flow() {
        let metrics = ConnectionMetrics::default();

        // Application writes 1000 bytes
        metrics.new_pending(1000);
        assert_eq!(metrics.pending_bytes(), 1000);
        assert_eq!(metrics.inflight_bytes(), 0);
        assert_eq!(metrics.acked_bytes(), 0);

        // Transport layer sends 600 bytes
        metrics.on_data_sent(600);
        assert_eq!(metrics.pending_bytes(), 400);
        assert_eq!(metrics.inflight_bytes(), 600);
        assert_eq!(metrics.acked_bytes(), 0);

        // Peer acknowledges 300 bytes
        metrics.on_data_acked(300);
        assert_eq!(metrics.pending_bytes(), 400);
        assert_eq!(metrics.inflight_bytes(), 300);
        assert_eq!(metrics.acked_bytes(), 300);

        // Transport layer sends remaining 400 bytes
        metrics.on_data_sent(400);
        assert_eq!(metrics.pending_bytes(), 0);
        assert_eq!(metrics.inflight_bytes(), 700);
        assert_eq!(metrics.acked_bytes(), 300);

        // Peer acknowledges all remaining data
        metrics.on_data_acked(700);
        assert_eq!(metrics.pending_bytes(), 0);
        assert_eq!(metrics.inflight_bytes(), 0);
        assert_eq!(metrics.acked_bytes(), 1000);
    }

    #[test]
    fn test_arc_connection_metrics() {
        let metrics = Arc::new(ConnectionMetrics::default());
        let metrics_clone = Arc::clone(&metrics);

        metrics.new_pending(100);
        assert_eq!(metrics_clone.pending_bytes(), 100);

        metrics_clone.on_data_sent(100);
        assert_eq!(metrics.inflight_bytes(), 100);
        assert_eq!(metrics.pending_bytes(), 0);
    }
}
