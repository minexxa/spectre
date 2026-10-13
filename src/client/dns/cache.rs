use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

type CacheKey = (String, u16);
type CacheVal = (Vec<u8>, Instant);
type CacheMap = HashMap<CacheKey, CacheVal>;

pub struct DnsCache {
    inner: Mutex<CacheMap>,
    capacity: usize,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    pub fn get(&self, domain: &str, qtype: u16) -> Option<Vec<u8>> {
        let mut g = self.inner.lock().ok()?;
        let key = (domain.to_ascii_lowercase(), qtype);
        if let Some((data, exp)) = g.get(&key) {
            if *exp > Instant::now() {
                return Some(data.clone());
            }
            g.remove(&key);
        }
        None
    }

    pub fn put(&self, domain: &str, qtype: u16, data: Vec<u8>, ttl: Duration) {
        if self.capacity == 0 {
            return;
        }
        if let Ok(mut g) = self.inner.lock() {
            if g.len() >= self.capacity {
                // simple eviction: clear half
                let n = g.len() / 2;
                let keys: Vec<_> = g.keys().take(n).cloned().collect();
                for k in keys {
                    g.remove(&k);
                }
            }
            g.insert(
                (domain.to_ascii_lowercase(), qtype),
                (data, Instant::now() + ttl),
            );
        }
    }
}
