//! DNS response cache with LRU eviction (in-memory only).
//!
//! Aligned with ant, minus the optional redb persistence (spectre has no
//! AppCache store — no cache dependency is introduced).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Entry {
    /// Wire response with transaction ID set to 0; callers patch the ID.
    body: Vec<u8>,
    expires: Instant,
}

pub struct DnsCache {
    inner: Mutex<Inner>,
}

struct Inner {
    map: HashMap<(String, u16), Entry>,
    order: VecDeque<(String, u16)>,
    capacity: usize,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
                capacity: capacity.max(1),
            }),
        }
    }

    pub fn get(&self, domain: &str, qtype: u16) -> Option<Vec<u8>> {
        let key = (domain.to_ascii_lowercase(), qtype);
        let mut g = self.inner.lock().ok()?;
        let now = Instant::now();
        if let Some(entry) = g.map.get(&key) {
            if entry.expires > now {
                let body = entry.body.clone();
                if let Some(pos) = g.order.iter().position(|k| k == &key) {
                    g.order.remove(pos);
                }
                g.order.push_back(key);
                return Some(body);
            }
            g.map.remove(&key);
            g.order.retain(|k| k != &key);
        }
        None
    }

    pub fn put(&self, domain: &str, qtype: u16, mut body: Vec<u8>, ttl: Duration) {
        if domain.is_empty() || body.len() < 12 {
            return;
        }
        // Zero the transaction ID: the cached body is query-agnostic, callers
        // patch the ID on every hit (apply_query_id).
        body[0] = 0;
        body[1] = 0;
        let key = (domain.to_ascii_lowercase(), qtype);
        let entry = Entry {
            body,
            expires: Instant::now() + ttl,
        };
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if g.map.contains_key(&key) {
            g.order.retain(|k| k != &key);
        }
        g.map.insert(key.clone(), entry);
        g.order.push_back(key);
        while g.map.len() > g.capacity {
            if let Some(old) = g.order.pop_front() {
                g.map.remove(&old);
            } else {
                break;
            }
        }
    }
}

/// Patch transaction ID of a cached response to match the query.
pub fn apply_query_id(response: &mut [u8], query: &[u8]) {
    if response.len() >= 2 && query.len() >= 2 {
        response[0] = query[0];
        response[1] = query[1];
    }
}

/// Best-effort min TTL from answer RRs (fallback when none found).
pub fn response_ttl_secs(resp: &[u8], fallback: u32) -> u32 {
    if resp.len() < 12 {
        return fallback;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut i = 12usize;
    // skip question
    while i < resp.len() {
        if resp[i] == 0 {
            i += 5; // null + type + class
            break;
        }
        if resp[i] >= 0xc0 {
            i += 2 + 4;
            break;
        }
        let l = resp[i] as usize;
        i += 1 + l;
    }
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        if i + 10 > resp.len() {
            break;
        }
        // name
        if resp[i] >= 0xc0 {
            i += 2;
        } else {
            while i < resp.len() && resp[i] != 0 {
                if resp[i] >= 0xc0 {
                    i += 1;
                    break;
                }
                let l = resp[i] as usize;
                i += 1 + l;
            }
            if i < resp.len() && resp[i] == 0 {
                i += 1;
            }
        }
        if i + 10 > resp.len() {
            break;
        }
        // type(2) class(2) ttl(4) rdlen(2)
        let ttl = u32::from_be_bytes([resp[i + 4], resp[i + 5], resp[i + 6], resp[i + 7]]);
        min_ttl = min_ttl.min(ttl);
        let rdlen = u16::from_be_bytes([resp[i + 8], resp[i + 9]]) as usize;
        i += 10 + rdlen;
    }
    if min_ttl == u32::MAX || min_ttl == 0 {
        fallback
    } else {
        min_ttl
    }
}
