//! Bounded RAM-only TLS keep-alive connection pool for DoH & DoT upstreams.
//!
//! Keeps up to 2 idle TLS sessions per upstream (max idle 30s) to cut uncached
//! DNS latency and mobile battery usage. Wiped immediately on stop or network change.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::upstream::EncryptedTlsStream;

const MAX_IDLE_PER_UPSTREAM: usize = 2;
const MAX_IDLE_AGE: Duration = Duration::from_secs(30);

pub struct UpstreamPool {
    pools: Mutex<HashMap<usize, VecDeque<(EncryptedTlsStream, Instant)>>>,
}

impl UpstreamPool {
    pub fn new() -> Self {
        Self {
            pools: Mutex::new(HashMap::new()),
        }
    }

    pub async fn take(&self, upstream_idx: usize) -> Option<EncryptedTlsStream> {
        let mut guard = self.pools.lock().await;
        let queue = guard.get_mut(&upstream_idx)?;
        let now = Instant::now();
        while let Some((stream, saved_at)) = queue.pop_front() {
            if now.duration_since(saved_at) < MAX_IDLE_AGE {
                return Some(stream);
            }
        }
        None
    }

    pub async fn put(&self, upstream_idx: usize, stream: EncryptedTlsStream) {
        let mut guard = self.pools.lock().await;
        let queue = guard.entry(upstream_idx).or_default();
        while queue.len() >= MAX_IDLE_PER_UPSTREAM {
            queue.pop_front();
        }
        queue.push_back((stream, Instant::now()));
    }

    pub async fn clear(&self) {
        self.pools.lock().await.clear();
    }
}

impl Default for UpstreamPool {
    fn default() -> Self {
        Self::new()
    }
}
