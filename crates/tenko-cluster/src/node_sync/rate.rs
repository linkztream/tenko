//! The bandwidth cap of a configuration stream (`[cluster] sync_kbps`, OPS-28): a token
//! bucket in bytes. The sender takes the size of each message before it sends it and waits
//! when the bucket is in debt, so the average rate of a stream stays at the cap; a large
//! snapshot is split into chunks of [`CHUNK_BYTES`] so the pacing is even.

use std::time::Duration;

use tokio::time::Instant;

/// The size of the chunks a capped stream sends a large payload in.
pub const CHUNK_BYTES: usize = 16 * 1024;

/// The smallest burst: the bucket holds at least this many bytes when full.
const MIN_BURST: f64 = 4096.0;

/// A token bucket over bytes.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Bytes per second.
    rate: f64,
    /// The most tokens the bucket holds.
    burst: f64,
    /// The tokens now; negative while the bucket is in debt.
    tokens: f64,
    /// When `tokens` was last brought up to date.
    last: Instant,
}

impl TokenBucket {
    /// A bucket for `kbps` kilobits per second (1,000 bits); `None` for 0, which is no cap.
    pub fn new(kbps: u64) -> Option<Self> {
        if kbps == 0 {
            return None;
        }
        #[allow(
            clippy::cast_precision_loss,
            reason = "a rate of up to 10 million kbps is exact in an f64"
        )]
        let rate = kbps as f64 * 125.0;
        let burst = (rate / 10.0).max(MIN_BURST);
        Some(Self {
            rate,
            burst,
            tokens: burst,
            last: Instant::now(),
        })
    }

    /// The rate in bytes per second.
    pub fn bytes_per_second(&self) -> f64 {
        self.rate
    }

    /// Takes `bytes` at `now` and returns how long the sender waits before sending them.
    pub fn delay_for(&mut self, bytes: usize, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        #[allow(
            clippy::cast_precision_loss,
            reason = "message sizes are far below 2^52 bytes"
        )]
        let size = bytes as f64;
        self.tokens -= size;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }

    /// Takes `bytes` and waits as long as the cap asks.
    pub async fn take(&mut self, bytes: usize) {
        let delay = self.delay_for(bytes, Instant::now());
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

/// Splits `payload` into chunks for a stream with the cap `kbps`: one piece without a cap.
pub fn chunks(payload: &[u8], kbps: u64) -> Vec<&[u8]> {
    if kbps == 0 || payload.len() <= CHUNK_BYTES {
        return vec![payload];
    }
    payload.chunks(CHUNK_BYTES).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cap_is_no_bucket() {
        assert!(TokenBucket::new(0).is_none());
        assert_eq!(chunks(&vec![0; 100_000], 0).len(), 1);
    }

    #[test]
    fn the_bucket_paces_to_the_rate() {
        // 80 kbps = 10,000 bytes per second; burst 4,096 bytes.
        let mut bucket = TokenBucket::new(80).expect("bucket");
        assert!((bucket.bytes_per_second() - 10_000.0).abs() < f64::EPSILON);
        let start = Instant::now();
        assert_eq!(bucket.delay_for(4096, start), Duration::ZERO);
        // The next 10,000 bytes have to wait one second.
        let delay = bucket.delay_for(10_000, start);
        assert!((delay.as_secs_f64() - 1.0).abs() < 1e-6, "{delay:?}");
        // After that second, the debt is paid and a small message waits a little.
        let later = start + Duration::from_secs(1);
        let delay = bucket.delay_for(1000, later);
        assert!((delay.as_secs_f64() - 0.1).abs() < 1e-6, "{delay:?}");
        // A long pause refills to the burst only.
        let idle = later + Duration::from_secs(60);
        assert_eq!(bucket.delay_for(4000, idle), Duration::ZERO);
        assert!(bucket.delay_for(4000, idle) > Duration::ZERO);
    }

    #[test]
    fn a_large_payload_is_chunked_under_a_cap() {
        let payload = vec![7u8; CHUNK_BYTES * 3 + 5];
        let parts = chunks(&payload, 64);
        assert_eq!(parts.len(), 4);
        assert_eq!(
            parts.iter().map(|part| part.len()).sum::<usize>(),
            payload.len()
        );
        assert_eq!(chunks(&payload[..10], 64).len(), 1);
    }
}
