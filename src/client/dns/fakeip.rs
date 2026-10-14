//! Fake-IP allocator (aligned with ant).
//!
//! Blacklist mode: every domain gets a fake address unless it hits an exclude
//! ruleset (then real DNS). Whitelist mode: only domains hitting a filter
//! ruleset get fake addresses.
//!
//! Mapping is in-memory only (spectre has no redb AppCache like ant).

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use tracing::debug;

pub struct FakeIpPool {
    v4: Option<V4Range>,
    v6: Option<V6Range>,
    by_domain4: Mutex<HashMap<String, Ipv4Addr>>,
    by_domain6: Mutex<HashMap<String, Ipv6Addr>>,
    by_ip: Mutex<HashMap<IpAddr, String>>,
}

struct V4Range {
    start: u32,
    end: u32,
    next: Mutex<u32>,
}

struct V6Range {
    start: u128,
    end: u128,
    next: Mutex<u128>,
}

impl FakeIpPool {
    pub fn new(v4: Option<&str>, v6: Option<&str>) -> Result<Self> {
        let v4 = match v4 {
            Some(s) if !s.is_empty() => Some(parse_v4(s)?),
            _ => None,
        };
        let v6 = match v6 {
            Some(s) if !s.is_empty() => Some(parse_v6(s)?),
            _ => None,
        };
        if v4.is_none() && v6.is_none() {
            bail!("fakeip mode requires fakeip-range and/or fakeip6-range");
        }
        Ok(Self {
            v4,
            v6,
            by_domain4: Mutex::new(HashMap::new()),
            by_domain6: Mutex::new(HashMap::new()),
            by_ip: Mutex::new(HashMap::new()),
        })
    }

    pub fn has_v4(&self) -> bool {
        self.v4.is_some()
    }

    pub fn has_v6(&self) -> bool {
        self.v6.is_some()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match &ip {
            IpAddr::V4(v4) => {
                let Some(r) = &self.v4 else {
                    return false;
                };
                let n = u32::from(*v4);
                n >= r.start && n <= r.end
            }
            IpAddr::V6(v6) => {
                let Some(r) = &self.v6 else {
                    return false;
                };
                let n = u128::from(*v6);
                n >= r.start && n <= r.end
            }
        }
    }

    pub fn domain_of(&self, ip: IpAddr) -> Option<String> {
        self.by_ip.lock().ok()?.get(&ip).cloned()
    }

    /// Allocate (or reuse) a fake address for `domain`. `v6` selects family.
    pub fn allocate(&self, domain: &str, v6: bool) -> Option<IpAddr> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return None;
        }
        if v6 {
            let ip = self.alloc6(&domain)?;
            Some(IpAddr::V6(ip))
        } else {
            let ip = self.alloc4(&domain)?;
            Some(IpAddr::V4(ip))
        }
    }

    fn alloc4(&self, domain: &str) -> Option<Ipv4Addr> {
        let range = self.v4.as_ref()?;
        let mut map = self.by_domain4.lock().ok()?;
        if let Some(ip) = map.get(domain) {
            return Some(*ip);
        }
        let mut next = range.next.lock().ok()?;
        let span = range.end.saturating_sub(range.start).saturating_add(1);
        if span == 0 {
            return None;
        }
        for _ in 0..span {
            let n = *next;
            *next = if n >= range.end {
                range.start
            } else {
                n + 1
            };
            let ip = Ipv4Addr::from(n);
            let mut by_ip = self.by_ip.lock().ok()?;
            if by_ip.contains_key(&IpAddr::V4(ip)) {
                continue;
            }
            by_ip.insert(IpAddr::V4(ip), domain.to_string());
            map.insert(domain.to_string(), ip);
            drop(by_ip);
            drop(map);
            drop(next);
            debug!("fakeip {domain} A -> {ip}");
            return Some(ip);
        }
        None
    }

    fn alloc6(&self, domain: &str) -> Option<Ipv6Addr> {
        let range = self.v6.as_ref()?;
        let mut map = self.by_domain6.lock().ok()?;
        if let Some(ip) = map.get(domain) {
            return Some(*ip);
        }
        let mut next = range.next.lock().ok()?;
        // Don't scan the whole /18; try a bounded number of collisions (same as ant).
        for _ in 0..4096 {
            let n = *next;
            *next = if n >= range.end {
                range.start
            } else {
                n + 1
            };
            let ip = Ipv6Addr::from(n);
            let mut by_ip = self.by_ip.lock().ok()?;
            if by_ip.contains_key(&IpAddr::V6(ip)) {
                continue;
            }
            by_ip.insert(IpAddr::V6(ip), domain.to_string());
            map.insert(domain.to_string(), ip);
            drop(by_ip);
            drop(map);
            drop(next);
            debug!("fakeip {domain} AAAA -> {ip}");
            return Some(ip);
        }
        None
    }
}

fn parse_v4(s: &str) -> Result<V4Range> {
    let (ip, prefix) = parse_cidr(s)?;
    let IpAddr::V4(v4) = ip else {
        bail!("fakeip-range must be IPv4 CIDR, got {s}");
    };
    if prefix > 32 {
        bail!("fakeip-range prefix out of range: {s}");
    }
    let host_bits = 32u32.saturating_sub(prefix as u32);
    let mask = if host_bits >= 32 {
        0u32
    } else {
        !((1u32 << host_bits) - 1)
    };
    let network = u32::from(v4) & mask;
    let broadcast = if host_bits >= 32 {
        u32::MAX
    } else {
        network | ((1u32 << host_bits) - 1)
    };
    // Skip network/broadcast when the range is large enough (aligned with ant/ipnet).
    let (start, end) = if prefix <= 30 {
        (network + 1, broadcast - 1)
    } else {
        (network, broadcast)
    };
    if start > end {
        bail!("fakeip-range {s} has no usable address");
    }
    Ok(V4Range {
        start,
        end,
        next: Mutex::new(start),
    })
}

fn parse_v6(s: &str) -> Result<V6Range> {
    let (ip, prefix) = parse_cidr(s)?;
    let IpAddr::V6(v6) = ip else {
        bail!("fakeip6-range must be IPv6 CIDR, got {s}");
    };
    if prefix > 128 {
        bail!("fakeip6-range prefix out of range: {s}");
    }
    let host_bits = 128u32.saturating_sub(prefix as u32);
    let mask = if host_bits >= 128 {
        0u128
    } else {
        !((1u128 << host_bits) - 1)
    };
    let network = u128::from(v6) & mask;
    let broadcast = if host_bits >= 128 {
        u128::MAX
    } else {
        network | ((1u128 << host_bits) - 1)
    };
    // ant: start = network + 1, end = broadcast
    let start = network.saturating_add(1);
    let end = broadcast;
    if start > end {
        bail!("fakeip6-range {s} has no usable address");
    }
    Ok(V6Range {
        start,
        end,
        next: Mutex::new(start),
    })
}

fn parse_cidr(s: &str) -> Result<(IpAddr, u8)> {
    let (addr, pref) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("CIDR expected host/prefix, got `{s}`"))?;
    let ip: IpAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("bad IP in `{s}`: {e}"))?;
    let prefix: u8 = pref
        .parse()
        .map_err(|e| anyhow::anyhow!("bad prefix in `{s}`: {e}"))?;
    let max = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        bail!("prefix /{prefix} out of range for {s}");
    }
    Ok((ip, prefix))
}

/// Build a minimal DNS response with one A or AAAA answer (flags aligned with ant).
pub fn build_fakeip_answer(query: &[u8], ip: IpAddr) -> Vec<u8> {
    let question_end = question_end(query).unwrap_or(12);
    let mut resp = Vec::with_capacity(question_end + 28);
    // ID
    if query.len() >= 2 {
        resp.extend_from_slice(&query[..2]);
    } else {
        resp.extend_from_slice(&[0, 0]);
    }
    // Flags: QR=1, RD=1, RA=1 (same as ant)
    resp.push(0x81);
    resp.push(0x80);
    // QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    if question_end > 12 && query.len() >= question_end {
        resp.extend_from_slice(&query[12..question_end]);
    }
    // Answer: pointer to qname at offset 12
    resp.extend_from_slice(&[0xC0, 0x0C]);
    match ip {
        IpAddr::V4(v4) => {
            resp.extend_from_slice(&1u16.to_be_bytes()); // A
            resp.extend_from_slice(&1u16.to_be_bytes()); // IN
            resp.extend_from_slice(&1u32.to_be_bytes()); // TTL
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            resp.extend_from_slice(&28u16.to_be_bytes()); // AAAA
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&1u32.to_be_bytes());
            resp.extend_from_slice(&16u16.to_be_bytes());
            resp.extend_from_slice(&v6.octets());
        }
    }
    resp
}

fn question_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < 12 {
        return None;
    }
    let mut i = 12;
    loop {
        if i >= msg.len() {
            return None;
        }
        let len = msg[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len >= 0xc0 {
            i += 1;
            break;
        }
        i += len;
    }
    if i + 4 > msg.len() {
        return None;
    }
    Some(i + 4)
}
