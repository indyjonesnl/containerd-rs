//! Per-key async serialization for idempotent/concurrent CRI operations.
//!
//! The CRI contract requires duplicate concurrent requests for the same object
//! (notably `PullImage` for the same reference) to be serialized rather than
//! racing — two concurrent pulls of one image would otherwise unpack into the
//! same chainID snapshot dir simultaneously. `KeyedLocks` hands out a per-key
//! async mutex so same-key callers run one at a time while different keys stay
//! concurrent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// A registry of per-key async mutexes.
#[derive(Clone, Default)]
pub struct KeyedLocks {
    inner: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

impl KeyedLocks {
    /// Acquire the lock for `key`. Callers sharing a key are serialized; callers
    /// with different keys proceed concurrently. Hold the returned guard for the
    /// critical section and drop it to release.
    ///
    /// Entries are retained for the process lifetime (one per distinct key ever
    /// used) — bounded by the set of image references on a node, like
    /// containerd's per-ref ingest locks.
    pub async fn guard(&self, key: &str) -> OwnedMutexGuard<()> {
        let m = {
            let mut map = self.inner.lock().unwrap();
            map.entry(key.to_string()).or_default().clone()
        };
        m.lock_owned().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};
    use std::time::Duration;

    #[tokio::test]
    async fn same_key_serializes() {
        let locks = KeyedLocks::default();
        let inside = Arc::new(AtomicBool::new(false));
        let overlapped = Arc::new(AtomicBool::new(false));
        let ran = Arc::new(AtomicU32::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let (l, b, o, r) = (
                locks.clone(),
                inside.clone(),
                overlapped.clone(),
                ran.clone(),
            );
            handles.push(tokio::spawn(async move {
                let _g = l.guard("image:x").await;
                if b.swap(true, SeqCst) {
                    o.store(true, SeqCst); // another holder was already inside
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
                b.store(false, SeqCst);
                r.fetch_add(1, SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(ran.load(SeqCst), 4);
        assert!(
            !overlapped.load(SeqCst),
            "same-key sections never overlapped"
        );
    }

    #[tokio::test]
    async fn different_keys_do_not_block() {
        let locks = KeyedLocks::default();
        let held = locks.guard("a").await;
        // A different key must be acquirable while "a" is held.
        let other = tokio::time::timeout(Duration::from_millis(200), locks.guard("b")).await;
        assert!(other.is_ok(), "different keys are independent");
        drop(held);
    }
}
