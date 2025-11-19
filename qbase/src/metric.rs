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
    /// Data written by application layer but not yet sent by transport layer (待发送数据量)
    pending_send_bytes: AtomicU64,
    /// Data sent by transport layer but not yet acknowledged by peer (已发送待确认数据量)
    sent_unacked_bytes: AtomicU64,
    /// Data sent and acknowledged by peer (已发送已确认数据量)
    sent_acked_bytes: AtomicU64,
}

impl ConnectionMetrics {
    /// Creates a new ConnectionMetrics instance with all counters set to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increments the pending send bytes counter when application writes data.
    ///
    /// Called when application layer writes data to a stream.
    pub fn add_pending_send(&self, bytes: u64) {
        self.pending_send_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Updates counters when transport layer sends new data.
    ///
    /// Increments sent_unacked_bytes and decrements pending_send_bytes.
    /// Called when transport layer sends new stream data.
    pub fn on_data_sent(&self, bytes: u64) {
        self.sent_unacked_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.pending_send_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Updates counters when data is acknowledged by peer.
    ///
    /// Increments sent_acked_bytes and decrements sent_unacked_bytes.
    /// Called when receiving acknowledgment for stream data.
    pub fn on_data_acked(&self, bytes: u64) {
        self.sent_acked_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.sent_unacked_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Gets the current amount of data pending to be sent.
    pub fn pending_send_bytes(&self) -> u64 {
        self.pending_send_bytes.load(Ordering::Relaxed)
    }

    /// Gets the current amount of data sent but not acknowledged.
    pub fn sent_unacked_bytes(&self) -> u64 {
        self.sent_unacked_bytes.load(Ordering::Relaxed)
    }

    /// Gets the total amount of data sent and acknowledged.
    pub fn sent_acked_bytes(&self) -> u64 {
        self.sent_acked_bytes.load(Ordering::Relaxed)
    }
}

/// Arc-wrapped ConnectionMetrics for shared ownership across the connection.
pub type ArcConnectionMetrics = Arc<ConnectionMetrics>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_metrics_new() {
        let metrics = ConnectionMetrics::new();
        assert_eq!(metrics.pending_send_bytes(), 0);
        assert_eq!(metrics.sent_unacked_bytes(), 0);
        assert_eq!(metrics.sent_acked_bytes(), 0);
    }

    #[test]
    fn test_add_pending_send() {
        let metrics = ConnectionMetrics::new();
        metrics.add_pending_send(100);
        assert_eq!(metrics.pending_send_bytes(), 100);
        metrics.add_pending_send(50);
        assert_eq!(metrics.pending_send_bytes(), 150);
    }

    #[test]
    fn test_on_data_sent() {
        let metrics = ConnectionMetrics::new();
        metrics.add_pending_send(200);
        metrics.on_data_sent(150);
        assert_eq!(metrics.pending_send_bytes(), 50);
        assert_eq!(metrics.sent_unacked_bytes(), 150);
    }

    #[test]
    fn test_on_data_acked() {
        let metrics = ConnectionMetrics::new();
        metrics.add_pending_send(200);
        metrics.on_data_sent(150);
        metrics.on_data_acked(100);
        assert_eq!(metrics.pending_send_bytes(), 50);
        assert_eq!(metrics.sent_unacked_bytes(), 50);
        assert_eq!(metrics.sent_acked_bytes(), 100);
    }

    #[test]
    fn test_full_data_flow() {
        let metrics = ConnectionMetrics::new();

        // Application writes 1000 bytes
        metrics.add_pending_send(1000);
        assert_eq!(metrics.pending_send_bytes(), 1000);
        assert_eq!(metrics.sent_unacked_bytes(), 0);
        assert_eq!(metrics.sent_acked_bytes(), 0);

        // Transport layer sends 600 bytes
        metrics.on_data_sent(600);
        assert_eq!(metrics.pending_send_bytes(), 400);
        assert_eq!(metrics.sent_unacked_bytes(), 600);
        assert_eq!(metrics.sent_acked_bytes(), 0);

        // Peer acknowledges 300 bytes
        metrics.on_data_acked(300);
        assert_eq!(metrics.pending_send_bytes(), 400);
        assert_eq!(metrics.sent_unacked_bytes(), 300);
        assert_eq!(metrics.sent_acked_bytes(), 300);

        // Transport layer sends remaining 400 bytes
        metrics.on_data_sent(400);
        assert_eq!(metrics.pending_send_bytes(), 0);
        assert_eq!(metrics.sent_unacked_bytes(), 700);
        assert_eq!(metrics.sent_acked_bytes(), 300);

        // Peer acknowledges all remaining data
        metrics.on_data_acked(700);
        assert_eq!(metrics.pending_send_bytes(), 0);
        assert_eq!(metrics.sent_unacked_bytes(), 0);
        assert_eq!(metrics.sent_acked_bytes(), 1000);
    }

    #[test]
    fn test_arc_connection_metrics() {
        let metrics = Arc::new(ConnectionMetrics::new());
        let metrics_clone = Arc::clone(&metrics);

        metrics.add_pending_send(100);
        assert_eq!(metrics_clone.pending_send_bytes(), 100);

        metrics_clone.on_data_sent(100);
        assert_eq!(metrics.sent_unacked_bytes(), 100);
        assert_eq!(metrics.pending_send_bytes(), 0);
    }
}
